package config

import (
	"github.com/spf13/viper"
	"log"
)

// Config holds the configuration settings for the application
type Config struct {
	PackageName  string `mapstructure:"package_name"`
	Version      string `mapstructure:"version"`
	Maintainer   string `mapstructure:"maintainer"`
	Description  string `mapstructure:"description"`
	Architecture string `mapstructure:"architecture"`
	Priority     string `mapstructure:"priority"`
	Section      string `mapstructure:"section"`
}

// LoadConfig reads the configuration from a file and populates the Config struct
func LoadConfig(configFile string) (*Config, error) {
	viper.SetConfigName(configFile)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// Validate checks the configuration for required fields
func (c *Config) Validate() error {
	if c.PackageName == "" {
		return log.Output(1, "Package name is required")
	}
	if c.Version == "" {
		return log.Output(1, "Version is required")
	}
	if c.Maintainer == "" {
		return log.Output(1, "Maintainer is required")
	}
	return nil
}
