package main

import _ "embed"

//go:embed dashboard.html
var dashboardHTML string

func renderDashboardHTML() string {
	return dashboardHTML
}
