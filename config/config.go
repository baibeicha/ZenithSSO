package config

import (
	"log"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	*viper.Viper
	filename string
	GRPC     GRPCConfig `mapstructure:"grpc"`
	SSO      SSOConfig  `mapstructure:"sso"`
}

type SSOConfig struct {
	Issuer string `mapstructure:"issuer"`
}

type GRPCConfig struct {
	Port int       `mapstructure:"port"`
	TLS  TLSConfig `mapstructure:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertPath string `mapstructure:"cert_path"`
	KeyPath  string `mapstructure:"key_path"`
}

func MustLoad(filename string) *Config {
	if filename == "" {
		filename = "config"
	}

	v := viper.New()

	v.SetConfigName(filename)

	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		log.Fatalf("error reading config: %v", err)
	}

	var cfg Config

	if err := v.Unmarshal(&cfg); err != nil {
		log.Fatalf("error parsing config into struct: %v", err)
	}

	if cfg.SSO.Issuer == "" {
		cfg.SSO.Issuer = "http://localhost:8080" // default
	}

	cfg.Viper = v
	cfg.filename = filename

	return &cfg
}

func (c *Config) GetServerPort() uint16 {
	return uint16(c.GetInt("server.port"))
}
