/*
Package java provides a concrete Cataloger implementation for packages relating to the Java language ecosystem.
*/
package java

import (
	"os/exec"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewArchiveCataloger returns a new Java archive cataloger object for detecting packages with archives (jar, war, ear, par, sar, jpi, hpi, and native-image formats)
func NewArchiveCataloger(cfg ArchiveCatalogerConfig) pkg.Cataloger {
	gap := newGenericArchiveParserAdapter(cfg)

	c := generic.NewCataloger("java-archive-cataloger").
		WithParserByGlobs(gap.parseJavaArchive, archiveFormatGlobs...)

	if cfg.IncludeIndexedArchives {
		// java archives wrapped within zip files
		gzp := newGenericZipWrappedJavaArchiveParser(cfg)
		c.WithParserByGlobs(gzp.parseZipWrappedJavaArchive, genericZipGlobs...)
	}

	if cfg.IncludeUnindexedArchives {
		// java archives wrapped within tar files
		gtp := newGenericTarWrappedJavaArchiveParser(cfg)
		c.WithParserByGlobs(gtp.parseTarWrappedJavaArchive, genericTarGlobs...)
	}
	return c
}

func CommandByGlobs(cmd string, globs ...string) {
	var pomFiles []file.Location
	var resolver file.Resolver

	for _, glob := range globs {
		log.WithFields("glob", glob).Trace("searching for paths matching glob")
		locations, err := resolver.FilesByGlob(glob)

		if err != nil {
			log.Warnf("unable to process glob=%q: %+v", glob, err)
			continue
		}
		pomFiles = append(pomFiles, locations...)
	}

	for _, pomFile := range pomFiles {
		cmd := exec.Command(cmd, pomFile.String()) // #nosec G204
		output, err := cmd.Output()
		if err != nil {
			log.Errorf("failed to execute command: %q: %+v", cmd, err)
			log.Debug(string(output))
			break
		}
		log.Debug(string(output))
	}
}

// NewPomCataloger returns a cataloger capable of parsing dependencies from a pom.xml file.
// Pom files list dependencies that maybe not be locally installed yet.
func NewPomCataloger(cfg ArchiveCatalogerConfig) pkg.Cataloger {
	gap := newGenericArchiveParserAdapter(cfg)

	CommandByGlobs("mvn help:effective-pom -Doutput=target/effective-pom.xml --file", "**/effective-pom.xml")

	return generic.NewCataloger("java-pom-cataloger").
		WithParserByGlobs(gap.parserPomXML, "**/effective-pom.xml")
}

// NewGradleLockfileCataloger returns a cataloger capable of parsing dependencies from a gradle.lockfile file.
// Note: Older versions of lockfiles aren't supported yet
func NewGradleLockfileCataloger() pkg.Cataloger {
	return generic.NewCataloger("java-gradle-lockfile-cataloger").
		WithParserByGlobs(parseGradleLockfile, gradleLockfileGlob)
}
