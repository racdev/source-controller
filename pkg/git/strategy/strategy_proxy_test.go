/*
Copyright 2021 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package strategy

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/fluxcd/pkg/gittestserver"
	. "github.com/onsi/gomega"

	"github.com/fluxcd/source-controller/pkg/git"
	"github.com/fluxcd/source-controller/pkg/git/gogit"
	"github.com/fluxcd/source-controller/pkg/git/libgit2"
)

// These tests are run in a different _test.go file because go-git uses the ProxyFromEnvironment function of the net/http package
// which caches the Proxy settings, hence not including other tests in the same file ensures a clean proxy setup for the tests to run.
func TestCheckoutStrategyForImplementation_Proxied(t *testing.T) {
	proxyAddr := "localhost:9999"

	type testCase struct {
		name          string
		gitImpl       git.Implementation
		url           string
		branch        string
		setupGitProxy func(g *WithT, proxy *goproxy.ProxyHttpServer, proxyGotRequest *bool) (*git.AuthOptions, func())
		usedProxy     bool
		getError      bool
	}

	cases := []testCase{
		{
			name:    "libgit2_HTTPS_PROXY",
			gitImpl: libgit2.Implementation,
			url:     "https://example.com/bar/test-reponame",
			branch:  "main",
			setupGitProxy: func(g *WithT, proxy *goproxy.ProxyHttpServer, proxyGotRequest *bool) (*git.AuthOptions, func()) {
				// Create the git server.
				gitServer, err := gittestserver.NewTempGitServer()
				g.Expect(err).ToNot(HaveOccurred())

				username := "test-user"
				password := "test-password"
				gitServer.Auth(username, password)
				gitServer.KeyDir(gitServer.Root())

				// Start the HTTPS server.
				examplePublicKey, err := os.ReadFile("testdata/certs/server.pem")
				g.Expect(err).ToNot(HaveOccurred())
				examplePrivateKey, err := os.ReadFile("testdata/certs/server-key.pem")
				g.Expect(err).ToNot(HaveOccurred())
				exampleCA, err := os.ReadFile("testdata/certs/ca.pem")
				g.Expect(err).ToNot(HaveOccurred())
				err = gitServer.StartHTTPS(examplePublicKey, examplePrivateKey, exampleCA, "example.com")
				g.Expect(err).ToNot(HaveOccurred())

				// Initialize a git repo.
				repoPath := "bar/test-reponame"
				err = gitServer.InitRepo("testdata/repo1", "main", repoPath)
				g.Expect(err).ToNot(HaveOccurred())

				u, err := url.Parse(gitServer.HTTPAddress())
				g.Expect(err).ToNot(HaveOccurred())

				var proxyHandler goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
					// Check if the host matches with the git server address and the user-agent is the expected git client.
					userAgent := ctx.Req.Header.Get("User-Agent")
					if strings.Contains(host, "example.com") && strings.Contains(userAgent, "libgit2") {
						*proxyGotRequest = true
						return goproxy.OkConnect, u.Host
					}
					return goproxy.OkConnect, host
				}
				proxy.OnRequest().HandleConnect(proxyHandler)

				return &git.AuthOptions{
						Transport: git.HTTPS,
						Username:  username,
						Password:  password,
						CAFile:    exampleCA,
					}, func() {
						os.RemoveAll(gitServer.Root())
						gitServer.StopHTTP()
					}
			},
			usedProxy: true,
			getError:  false,
		},
		{
			name:    "gogit_HTTP_PROXY",
			gitImpl: gogit.Implementation,
			url:     "http://example.com/bar/test-reponame",
			branch:  "main",
			setupGitProxy: func(g *WithT, proxy *goproxy.ProxyHttpServer, proxyGotRequest *bool) (*git.AuthOptions, func()) {
				// Create the git server.
				gitServer, err := gittestserver.NewTempGitServer()
				g.Expect(err).ToNot(HaveOccurred())

				username := "test-user"
				password := "test-password"
				gitServer.Auth(username, password)
				gitServer.KeyDir(gitServer.Root())

				g.Expect(gitServer.StartHTTP()).ToNot(HaveOccurred())

				// Initialize a git repo.
				err = gitServer.InitRepo("testdata/repo1", "main", "bar/test-reponame")
				g.Expect(err).ToNot(HaveOccurred())

				u, err := url.Parse(gitServer.HTTPAddress())
				g.Expect(err).ToNot(HaveOccurred())

				var proxyHandler goproxy.FuncReqHandler = func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
					userAgent := req.Header.Get("User-Agent")
					if strings.Contains(req.Host, "example.com") && strings.Contains(userAgent, "git") {
						*proxyGotRequest = true
						req.Host = u.Host
						req.URL.Host = req.Host
					}
					return req, nil
				}
				proxy.OnRequest().Do(proxyHandler)

				return &git.AuthOptions{
						Transport: git.HTTP,
						Username:  username,
						Password:  password,
					}, func() {
						os.RemoveAll(gitServer.Root())
						gitServer.StopHTTP()
					}
			},
			usedProxy: true,
			getError:  false,
		},
		{
			name:    "gogit_HTTPS_PROXY",
			gitImpl: gogit.Implementation,
			url:     "https://github.com/git-fixtures/basic",
			branch:  "master",
			setupGitProxy: func(g *WithT, proxy *goproxy.ProxyHttpServer, proxyGotRequest *bool) (*git.AuthOptions, func()) {
				var proxyHandler goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
					userAgent := ctx.Req.Header.Get("User-Agent")
					if strings.Contains(host, "github.com") && strings.Contains(userAgent, "Go-http-client") {
						*proxyGotRequest = true
					}
					return goproxy.OkConnect, host
				}
				proxy.OnRequest().HandleConnect(proxyHandler)

				// go-git does not allow to use an HTTPS proxy and a custom root CA at the same time.
				// See https://github.com/fluxcd/source-controller/pull/524#issuecomment-1006673163.
				return nil, func() {}
			},
			usedProxy: true,
			getError:  false,
		},
		{
			name:    "gogit_NO_PROXY",
			gitImpl: gogit.Implementation,
			url:     "https://somewhere.com/bar/test-reponame",
			branch:  "main",
			setupGitProxy: func(g *WithT, proxy *goproxy.ProxyHttpServer, proxyGotRequest *bool) (*git.AuthOptions, func()) {
				var proxyHandler goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
					// we shouldnt hit the proxy so we just want to check for any interaction
					*proxyGotRequest = true
					return goproxy.OkConnect, host
				}
				proxy.OnRequest().HandleConnect(proxyHandler)

				return nil, func() {}
			},
			usedProxy: false,
			getError:  true,
		},
		// TODO: Add a NO_PROXY test for libgit2 once the version of libgit2 used by the source controller is updated to a version that includes
		// the NO_PROXY functionlity
	}

	testFunc := func(tt testCase) func(t *testing.T) {
		return func(t *testing.T) {
			g := NewWithT(t)

			// Run a proxy server.
			proxy := goproxy.NewProxyHttpServer()
			proxy.Verbose = true

			proxyGotRequest := false
			authOpts, cleanup := tt.setupGitProxy(g, proxy, &proxyGotRequest)
			defer cleanup()

			proxyServer := http.Server{
				Addr:    proxyAddr,
				Handler: proxy,
			}
			go proxyServer.ListenAndServe()
			defer proxyServer.Close()

			// Set the proxy env vars for both HTTP and HTTPS because go-git caches them.
			os.Setenv("HTTPS_PROXY", fmt.Sprintf("http://%s", proxyAddr))
			defer os.Unsetenv("HTTPS_PROXY")

			os.Setenv("HTTP_PROXY", fmt.Sprintf("http://%s", proxyAddr))
			defer os.Unsetenv("HTTP_PROXY")

			os.Setenv("NO_PROXY", "somewhere.com")
			defer os.Unsetenv("NO_PROXY")

			// Checkout the repo.
			checkoutStrategy, err := CheckoutStrategyForImplementation(context.TODO(), tt.gitImpl, git.CheckoutOptions{
				Branch: tt.branch,
			})
			g.Expect(err).ToNot(HaveOccurred())

			tmpDir, err := os.MkdirTemp("", "test-checkout")
			g.Expect(err).ToNot(HaveOccurred())
			defer os.RemoveAll(tmpDir)

			_, err = checkoutStrategy.Checkout(context.TODO(), tmpDir, tt.url, authOpts)
			if tt.getError {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			_ = proxyGotRequest
			g.Expect(proxyGotRequest).To(Equal(tt.usedProxy))
		}
	}

	// Run the test cases against the git implementations.
	for _, tt := range cases {
		t.Run(tt.name, testFunc(tt))
	}
}
