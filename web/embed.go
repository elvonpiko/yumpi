package web

import "embed"

// FS is the dashboard. Fonts are vendored so the page does not call the network.
//
//go:embed index.html styles.css app.js favicon.svg favicon.png favicon-180.png fonts/*
var FS embed.FS
