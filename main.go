// Package traefik_maintenance a maintenance page plugin.
package traefik_maintenance

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"text/template"
)

// Config the plugin configuration.
type Config struct {
	Enabled          bool     `json:"enabled"`
	Filename         string   `json:"filename"`
	TriggerFilename  string   `json:"triggerFilename"`
	HttpResponseCode int      `json:"httpResponseCode"`
	HttpContentType  string   `json:"httpContentType"`
	IpAllowList      []string `json:"ipAllowList"`
	DenyUri          []string `json:"denyUri"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Enabled:          false,
		Filename:         "",
		TriggerFilename:  "",
		HttpResponseCode: http.StatusServiceUnavailable,
		HttpContentType:  "text/html; charset=utf-8",
		IpAllowList:      []string{},
		DenyUri:          []string{},
	}
}

// MaintenancePage a maintenance page plugin.
type MaintenancePage struct {
	next             http.Handler
	enabled          bool
	filename         string
	triggerFilename  string
	httpResponseCode int
	HttpContentType  string
	IpAllowList      []string
	DenyUri          []string
	name             string
	template         *template.Template
}

// New created a new MaintenancePage plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Filename) == 0 {
		return nil, fmt.Errorf("filename cannot be empty")
	}

	return &MaintenancePage{
		enabled:          config.Enabled,
		filename:         config.Filename,
		triggerFilename:  config.TriggerFilename,
		httpResponseCode: config.HttpResponseCode,
		HttpContentType:  config.HttpContentType,
		IpAllowList:      config.IpAllowList,
		DenyUri:          config.DenyUri,
		next:             next,
		name:             name,
		template:         template.New("MaintenancePage").Delims("[[", "]]"),
	}, nil
}

func (a *MaintenancePage) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if a.maintenanceEnabled() && (a.checkIgnore(req) || a.checkDenyUri(req)) {
		// Return the maintenance page
		bytes, err := os.ReadFile(a.filename)
		if err == nil {
			rw.Header().Add("Content-Type", a.HttpContentType)
			rw.WriteHeader(a.httpResponseCode)
			_, err = rw.Write(bytes)
			if err == nil {
				return
			} else {
				log.Printf("Could not serve maintenance template %s: %s", a.filename, err)
			}
		} else {
			log.Printf("Could not read maintenance template %s: %s", a.filename, err)
		}
	}

	a.next.ServeHTTP(rw, req)
}

// Indicates if maintenance mode has been enabled
func (a *MaintenancePage) maintenanceEnabled() bool {
	if !a.enabled {
		return false
	}

	if a.enabled && len(a.triggerFilename) == 0 {
		return true
	}

	// Check if the trigger exists
	if _, err := os.Stat(a.triggerFilename); err == nil {
		return true
	}

	return false
}

func (a *MaintenancePage) checkIgnore(req *http.Request) bool {
	remoteAddr := requestGetRemoteAddress(req)
	// log.Printf("Request received: URL=%s, RemoteAddr=%s", req.URL.String(), remoteAddr)

	// Check if IpAllowList is not empty and if req.RemoteAddr is not in the allow list
	if len(a.IpAllowList) > 0 {
		// log.Printf("%v", a.IpAllowList)
		for _, allowedIP := range a.IpAllowList {
			_, ipNet, err := net.ParseCIDR(allowedIP)
			if err != nil {
				log.Printf("Could not parse allowedIP '%s': %v", allowedIP, err)
				continue
			}

			ip := net.ParseIP(remoteAddr)
			if ipNet.Contains(ip) {
				// log.Printf("Request from %s is allowed.", req.RemoteAddr)
				return false // Request is allowed, do not ignore
			}
		}
		// log.Printf("Request from %s is not allowed.", req.RemoteAddr)
		return true // Request is ignored
	}

	// log.Println("IpAllowList is empty, all requests are deny.")
	return true // All request is ignored
}

func ipAddrFromRemoteAddr(s string) string {
	idx := strings.LastIndex(s, ":")
	if idx == -1 {
		return s
	}
	return s[:idx]
}

func requestGetRemoteAddress(r *http.Request) string {
	hdr := r.Header
	hdrRealIP := hdr.Get("X-Real-Ip")
	hdrForwardedFor := hdr.Get("X-Forwarded-For")
	if hdrRealIP == "" && hdrForwardedFor == "" {
		return ipAddrFromRemoteAddr(r.RemoteAddr)
	}

	if hdrForwardedFor != "" {
		parts := strings.Split(hdrForwardedFor, ",")
		for i, p := range parts {
			parts[i] = strings.TrimSpace(p)
		}

		return parts[0]
	}
	return hdrRealIP
}

func (a *MaintenancePage) checkDenyUri(req *http.Request) bool {
	reqUrl := req.URL.String()
	log.Printf("URL: %s", reqUrl)
	if len(a.DenyUri) > 0 {
		for _, pattern := range a.DenyUri {
			log.Printf("URL: %s | Pattern: %s", reqUrl, pattern)
			denyPattern, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}

			if denyPattern.MatchString(reqUrl) {
				return true
			}
		}
	}
	return false
}
