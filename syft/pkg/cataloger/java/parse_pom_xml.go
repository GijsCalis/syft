package java

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"

	"github.com/saintfish/chardet"
	"github.com/vifraa/gopom"
	"golang.org/x/net/html/charset"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// MavenCoordinate is the unique identifier for a package in Maven.
type MavenCoordinate struct {
	GroupID    string
	ArtifactID string
	Version    string
}

// GroupId and ArtifactId of (managed) dependencies
type GroupArtifact struct {
	GroupID    string
	ArtifactID string
}

const pomXMLGlob = "*pom.xml"

var propertyMatcher = regexp.MustCompile("[$][{][^}]+[}]")

// Map containing all pom.xml files that have been parsed. Used for caching as pom files (might) have been downloaded from the internet
var parsedPomFilesCache map[MavenCoordinate]*gopom.Project = make(map[MavenCoordinate]*gopom.Project)

func (gap genericArchiveParserAdapter) parserPomXML(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	pom, err := decodePomXML(reader)

	if err != nil {
		return nil, nil, err
	}

	var pkgs []pkg.Package

	// Add all properties defined in parent poms to this project for resolving properties later on.
	if pom.Parent != nil {
		var allProperties map[string]string = make(map[string]string)
		getPropertiesFromParentPoms(
			ctx, allProperties, *pom.Parent.GroupID, *pom.Parent.ArtifactID, *pom.Parent.Version, gap.cfg, nil)
		log.Debugf("parserPomXML - allProperties count: %i", len(allProperties))
		addPropertiesToProject(&pom, allProperties)
		log.Debugf("project Properties count: %i", len(pom.Properties.Entries))
	}

	for _, dep := range *getPomDependencies(&pom) {
		log.Debugf("parserPomXML - dependency: [%s, %s, %s]", *dep.GroupID, *dep.ArtifactID)
		p := newPackageFromPom(
			ctx,
			pom,
			dep,
			gap.cfg,
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)
		if p.Name == "" {
			continue
		}

		pkgs = append(pkgs, p)

		if len(p.Version) == 0 || strings.HasPrefix(p.Version, "${") {
			log.Infof("Found artifact without version: %s:%s, version: %q", *dep.GroupID, *dep.ArtifactID, p.Version)
		}
	}

	return pkgs, nil, nil
}

func parsePomXMLProject(ctx context.Context, path string, reader io.Reader, location file.Location, cfg ArchiveCatalogerConfig) (*parsedPomProject, error) {
	pom, err := decodePomXML(reader)
	if err != nil {
		return nil, err
	}

	// Add all properties defined in parent poms to this project for resolving properties later on.
	if pom.Parent != nil {
		var allProperties map[string]string = make(map[string]string)
		getPropertiesFromParentPoms(
			ctx, allProperties, *pom.Parent.GroupID, *pom.Parent.ArtifactID, *pom.Parent.Version, cfg, nil)

		log.Debugf("parsePomXMLProject - allProperties count: %i", len(allProperties))
		addPropertiesToProject(&pom, allProperties)
		log.Debugf("2 project Properties count: %i", len(pom.Properties.Entries))
	}

	return newPomProject(path, pom, location), nil
}

func newPomProject(path string, p gopom.Project, location file.Location) *parsedPomProject {
	artifactID := safeString(p.ArtifactID)
	name := safeString(p.Name)
	projectURL := safeString(p.URL)

	var licenses []pkg.License
	if p.Licenses != nil {
		for _, license := range *p.Licenses {
			var licenseName, licenseURL string
			if license.Name != nil {
				licenseName = *license.Name
			}
			if license.URL != nil {
				licenseURL = *license.URL
			}

			if licenseName == "" && licenseURL == "" {
				continue
			}

			licenses = append(licenses, pkg.NewLicenseFromFields(licenseName, licenseURL, &location))
		}
	}

	log.WithFields("path", path, "artifactID", artifactID, "name", name, "projectURL", projectURL).Trace("parsing pom.xml")
	return &parsedPomProject{
		JavaPomProject: &pkg.JavaPomProject{
			Path:        path,
			Parent:      pomParent(p, p.Parent),
			GroupID:     resolveProperty(p, p.GroupID, "groupId"),
			ArtifactID:  artifactID,
			Version:     resolveProperty(p, p.Version, "version"),
			Name:        name,
			Description: cleanDescription(p.Description),
			URL:         projectURL,
		},
		Licenses: licenses,
	}
}

func newPackageFromPom(ctx context.Context, pom gopom.Project, dep gopom.Dependency, cfg ArchiveCatalogerConfig, locations ...file.Location) pkg.Package {
	groupId := resolveProperty(pom, dep.GroupID, "groupId")
	artifactId := resolveProperty(pom, dep.ArtifactID, "artifactId")

	m := pkg.JavaArchive{
		PomProperties: &pkg.JavaPomProperties{
			GroupID:    groupId,
			ArtifactID: artifactId,
			Scope:      resolveProperty(pom, dep.Scope, "scope"),
		},
	}

	name := safeString(dep.ArtifactID)
	version := resolveProperty(pom, dep.Version, "version")
	log.Infof("New dependency: [%s, %s, %s].", groupId, artifactId, version)
	var allProperties map[string]string = make(map[string]string)
	addMissingPropertiesFromProject(allProperties, &pom)

	licenses := make([]pkg.License, 0)
	if cfg.UseNetwork {
		if version == "" {
			// If we have no version then let's try to get it from a parent pom DependencyManagement section
			version = recursivelyFindVersionFromManagedOrInherited(ctx, *dep.GroupID, *dep.ArtifactID, &pom, cfg, allProperties, nil)
			log.Info("return 3")
			version = resolveProperty(pom, &version, "version")
		} else if strings.HasPrefix(version, "${") {
			log.Error("===>THIS SHOULD NOT HAPPEN!")
			// If we are missing the property for this version, search the pom hierarchy for it.
			if pom.Parent != nil {
				getPropertiesFromParentPoms(ctx, allProperties, *pom.Parent.GroupID, *pom.Parent.ArtifactID, *pom.Parent.Version,
					cfg, nil)
				log.Debugf("newPackageFromPom - allProperties count: %i", len(allProperties))
				addPropertiesToProject(&pom, allProperties)
				log.Debugf("2 project Properties count: %i", len(pom.Properties.Entries))
			}
			// version = resolveProperty(pom, &version, "version")
			version = resolveProperty(pom, &version, getPropertyName(version))
		}
		if isPropertyResolved(version) {

			parentLicenses := recursivelyFindLicensesFromParentPom(
				ctx,
				m.PomProperties.GroupID,
				m.PomProperties.ArtifactID,
				version,
				cfg)

			if len(parentLicenses) > 0 {
				for _, licenseName := range parentLicenses {
					licenses = append(licenses, pkg.NewLicenseFromFields(licenseName, "", nil))
				}
			}
		} else {
			log.Warnf("Could not determine version for package: [%s, %s]", groupId, artifactId)
		}
	}

	if strings.HasPrefix(version, "${") {
		log.Warnf("Got unresolved version '%s' for artifact: %s", version, name)
	}

	p := pkg.Package{
		Name:      name,
		Version:   version,
		Locations: file.NewLocationSet(locations...),
		Licenses:  pkg.NewLicenseSet(licenses...),
		PURL:      packageURL(name, version, m),
		Language:  pkg.Java,
		Type:      pkg.JavaPkg, // TODO: should we differentiate between packages from jar/war/zip versus packages from a pom.xml that were not installed yet?
		Metadata:  m,
	}

	p.SetID()

	return p
}

func decodePomXML(content io.Reader) (project gopom.Project, err error) {
	inputReader, err := getUtf8Reader(content)
	if err != nil {
		return project, fmt.Errorf("unable to read pom.xml: %w", err)
	}

	decoder := xml.NewDecoder(inputReader)
	// when an xml file has a character set declaration (e.g. '<?xml version="1.0" encoding="ISO-8859-1"?>') read that and use the correct decoder
	decoder.CharsetReader = charset.NewReaderLabel

	if err := decoder.Decode(&project); err != nil {
		return project, fmt.Errorf("unable to unmarshal pom.xml: %w", err)
	}

	// For modules groupID and version are almost always inherited from parent pom
	if project.GroupID == nil && project.Parent != nil {
		project.GroupID = project.Parent.GroupID
	}
	if project.Version == nil && project.Parent != nil {
		project.Version = project.Parent.Version
	}

	// If missing, add maven built-in version property often used in multi-module projects
	if project.Version != nil {
		if project.Properties == nil {
			var props gopom.Properties
			props.Entries = make(map[string]string)
			props.Entries["project.version"] = *project.Version
			project.Properties = &props
		} else {
			project.Properties.Entries["project.version"] = *project.Version
		}
	}
	// Store in cache
	parsedPomFilesCache[MavenCoordinate{*project.GroupID, *project.ArtifactID, *project.Version}] = &project
	return project, nil
}

func getUtf8Reader(content io.Reader) (io.Reader, error) {
	pomContents, err := io.ReadAll(content)
	if err != nil {
		return nil, err
	}

	detector := chardet.NewTextDetector()
	detection, err := detector.DetectBest(pomContents)

	var inputReader io.Reader
	if err == nil && detection != nil {
		if detection.Charset == "UTF-8" {
			inputReader = bytes.NewReader(pomContents)
		} else {
			inputReader, err = charset.NewReaderLabel(detection.Charset, bytes.NewReader(pomContents))
			if err != nil {
				return nil, fmt.Errorf("unable to get encoding: %w", err)
			}
		}
	} else {
		// we could not detect the encoding, but we want a valid file to read. Replace unreadable
		// characters with the UTF-8 replacement character.
		inputReader = strings.NewReader(strings.ToValidUTF8(string(pomContents), "�"))
	}
	return inputReader, nil
}

func pomParent(pom gopom.Project, parent *gopom.Parent) (result *pkg.JavaPomParent) {
	if parent == nil {
		return nil
	}

	artifactID := safeString(parent.ArtifactID)
	result = &pkg.JavaPomParent{
		GroupID:    resolveProperty(pom, parent.GroupID, "groupId"),
		ArtifactID: artifactID,
		Version:    resolveProperty(pom, parent.Version, "version"),
	}

	if result.GroupID == "" && result.ArtifactID == "" && result.Version == "" {
		return nil
	}
	return result
}

func cleanDescription(original *string) (cleaned string) {
	if original == nil {
		return ""
	}
	descriptionLines := strings.Split(*original, "\n")
	for _, line := range descriptionLines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		cleaned += line + " "
	}
	return strings.TrimSpace(cleaned)
}

// resolveProperty emulates some maven property resolution logic by looking in the project's variables
// as well as supporting the project expressions like ${project.parent.groupId}.
// If no match is found, the entire expression including ${} is returned
//
//nolint:gocognit
func resolveProperty(pom gopom.Project, propertyValue *string, propertyName string) string {
	propertyCase := safeString(propertyValue)
	if !strings.Contains(propertyCase, "${") {
		//nothing to resolve
		// log.Tracef("resolving property: value [%s] contains no variable", propertyName)
		return propertyCase
	}

	log.WithFields("existingPropertyValue", propertyCase, "propertyName", propertyName).Trace("resolving property")
	return propertyMatcher.ReplaceAllStringFunc(propertyCase, func(match string) string {
		entries := pomProperties(pom)
		value := resolveRecursiveByPropertyName(entries, match)
		if isPropertyResolved(value) {
			log.WithFields("PropertyValue", value, "propertyName", match).Trace("resolved property")
			return value
		}

		// if we don't find anything directly in the pom properties,
		// see if we have a project.x expression and process this based
		// on the xml tags in gopom
		propertyName := strings.TrimSpace(match[2 : len(match)-1]) // remove leading ${ and trailing }
		parts := strings.Split(propertyName, ".")
		numParts := len(parts)
		if numParts > 1 && strings.TrimSpace(parts[0]) == "project" {
			pomValue := reflect.ValueOf(pom)
			pomValueType := pomValue.Type()
			for partNum := 1; partNum < numParts; partNum++ {
				if pomValueType.Kind() != reflect.Struct {
					break
				}
				part := parts[partNum]
				for fieldNum := 0; fieldNum < pomValueType.NumField(); fieldNum++ {
					f := pomValueType.Field(fieldNum)
					tag := f.Tag.Get("xml")
					tag = strings.Split(tag, ",")[0]
					// a segment of the property name matches the xml tag for the field,
					// so we need to recurse down the nested structs or return a match
					// if we're done.
					if part == tag {
						pomValue = pomValue.Field(fieldNum)
						pomValueType = pomValue.Type()
						if pomValueType.Kind() == reflect.Ptr {
							// we were recursing down the nested structs, but one of the steps
							// we need to take is a nil pointer, so give up and return the original match
							if pomValue.IsNil() {
								return match
							}
							pomValue = pomValue.Elem()
							if !pomValue.IsZero() {
								// we found a non-zero value whose tag matches this part of the property name
								pomValueType = pomValue.Type()
							}
						}
						// If this was the last part of the property name, return the value
						if partNum == numParts-1 {
							value := fmt.Sprintf("%v", pomValue.Interface())
							log.WithFields("existingPropertyValue", value, "propertyName", propertyName).Trace("resolved property")
							return value
						}
						break
					}
				}
			}
		}
		return match
	})
}

func pomProperties(p gopom.Project) map[string]string {
	if p.Properties != nil {
		return p.Properties.Entries
	}
	return map[string]string{}
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
