package main

import (
	"html/template"
	"net/http"
)

type page struct {
	Title       string
	Description string
	Nav         string
}

// every route this host serves as HTML. the exhibits are deliberately absent
// from the navigation: they exist so a bug report can link to a live
// reproduction, not to be browsed
var pageSpecs = map[string]struct {
	file string
	page page
}{
	"/": {"echo.html", page{
		Title:       "WebTransport Echo",
		Description: "A public WebTransport echo server and test client. Send datagrams and streams and get them straight back, and see which endpoints your own browser will establish a session against.",
		Nav:         "echo",
	}},
	"/compat": {"compat.html", page{
		Title:       "WebTransport compatibility — Safari, iOS, Chrome and Firefox",
		Description: "What each engine requires of a WebTransport server, what it silently discards, and what breaks. Safari and iOS in detail, tested live against a public echo.",
		Nav:         "compat",
	}},
	"/exhibits/apple": {"exhibit-apple.html", page{
		Title:       "Exhibit — iOS 27 refuses valid WebTransport handshakes",
		Description: "Two servers advertising byte-identical h3 SETTINGS and QUIC transport parameters. Safari on iOS 27 establishes a session against one and refuses the other.",
	}},
	"/exhibits/quic-go": {"exhibit-quicgo.html", page{
		Title:       "Exhibit — quic-go and webtransport-go",
		Description: "Three reproducible findings against webtransport-go and quic-go, each testable live against a public echo.",
	}},
}

var templates = map[string]*template.Template{}

func parsePages() {
	for route, spec := range pageSpecs {
		templates[route] = template.Must(template.ParseFS(pagesFS,
			"web/pages/layout.html", "web/pages/"+spec.file))
	}
}

func renderPage(w http.ResponseWriter, route string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates[route].ExecuteTemplate(w, "layout", pageSpecs[route].page); err != nil {
		// the response is already partly written by the time a template can
		// fail, so there is nothing useful to say to the client
		return
	}
}
