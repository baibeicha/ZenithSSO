package configs

import (
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	*viper.Viper
	filename string
}

func NewConfig(filename string) (*Config, error) {
	if filename == "" {
		filename = "config"
	}

	v := viper.New()

	v.SetConfigName(filename)

	v.AddConfigPath(".")
	v.AddConfigPath("./configs")

	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	return &Config{
		filename: filename,
		Viper:    v,
	}, nil
}

func (c *Config) GetServerPort() uint16 {
	return uint16(c.GetInt("server.port"))
}
