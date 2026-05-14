package config

type Datasource struct {
	Url      string
	DB       string
	User     string
	Password string
	SslMode  string
}

func NewDatasourceFromConfig(cfg *Config) *Datasource {
	return &Datasource{
		Url:      cfg.GetString("datasource.url"),
		DB:       cfg.GetString("datasource.db"),
		User:     cfg.GetString("datasource.user"),
		Password: cfg.GetString("datasource.password"),
		SslMode:  cfg.GetString("datasource.ssl_mode"),
	}
}
