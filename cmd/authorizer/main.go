package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/crewjam/saml/samlsp"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	authorizer "github.com/dzeromsk/ingress-saml-authorizer"
)

var (
	configFile    = flag.String("config", "config.yaml", "Path to config file")
	printMetadata = flag.Bool("print-metadata", false, "Print metadata on stdout and exit")
)

func main() {
	flag.Parse()

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalln("can't initialize zap logger:", err)
	}
	defer logger.Sync()

	f, err := os.Open(*configFile)
	if err != nil {
		logger.Error("setup", zap.Error(err))
	}
	defer f.Close()

	d := yaml.NewDecoder(f)

	var config authorizer.Config
	if err := d.Decode(&config); err != nil {
		logger.Error("setup", zap.Error(err))
	}

	keyPair, err := tls.LoadX509KeyPair(config.CertificateFile, config.KeyFile)
	if err != nil {
		logger.Error("setup", zap.Error(err))
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		logger.Error("setup", zap.Error(err))
	}

	idpMetadataURL, err := url.Parse(config.IDPMetadataURL)
	if err != nil {
		logger.Error("setup", zap.Error(err))
	}

	rootURL, err := url.Parse(config.URL)
	if err != nil {
		logger.Error("setup", zap.Error(err))
	}

	sp, _ := samlsp.New(samlsp.Options{
		EntityID:            config.EntityID,
		AllowIDPInitiated:   config.AllowIDPInitiated,
		DefaultRedirectURI:  config.DefaultRedirectURI,
		SignRequest:         config.SignRequest,
		UseArtifactResponse: config.UseArtifactResponse,
		ForceAuthn:          config.ForceAuthn,
		URL:                 *rootURL,
		Key:                 keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:         keyPair.Leaf,
		// IDPMetadata:         idpMetadata,
	})

	if *printMetadata {
		// Usefull for helm installation hook jobs to autoregister our SP
		buf, _ := xml.MarshalIndent(sp.ServiceProvider.Metadata(), "", "  ")
		os.Stdout.Write(buf)
		return
	}

	// log.Println("Config:")
	// spew.Dump(config)

	logger.Info("Fetching IdP metadata", zap.String("url", idpMetadataURL.String()))

	sp.ServiceProvider.IDPMetadata, err = samlsp.FetchMetadata(
		context.Background(), http.DefaultClient, *idpMetadataURL)
	if err != nil {
		logger.Error("setup", zap.Error(err))
	}

	s := &authorizer.AuthService{
		SP:                 sp.Session,
		M:                  sp,
		RootURL:            rootURL,
		RequiredAttributes: config.RequireAttribute,
		Log:                logger,
	}
	http.HandleFunc("/saml/auth", s.Auth)
	http.HandleFunc("/saml/signin", s.Signin)
	http.HandleFunc("/saml/whoami", s.Whoami)
	http.Handle("/saml/", sp)

	logger.Info("Listening", zap.String("addr", config.Addr))
	if err := http.ListenAndServe(config.Addr, nil); err != nil {
		logger.Error("Listening", zap.Error(err))
	}
}
