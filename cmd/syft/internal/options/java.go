package options

type javaConfig struct {
	UseNetwork              bool   `yaml:"use-network" json:"use-network" mapstructure:"use-network"`
	UseMaven                bool   `yaml:"use-maven" json:"use-maven" mapstructure:"use-maven"`
	MavenURL                string `yaml:"maven-url" json:"maven-url" mapstructure:"maven-url"`
	MaxParentRecursiveDepth int    `yaml:"max-parent-recursive-depth" json:"max-parent-recursive-depth" mapstructure:"max-parent-recursive-depth"`
}
