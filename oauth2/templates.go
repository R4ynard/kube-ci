package oauth2

import (
	"html/template"
)

var errorTmpl = `
<html>
	<head>
		<title>login failed</title>
	</head>
	<body>
		could not log in
	</body>
</html> `

func loadTemplates() *template.Template {
	return template.Must(template.New("errors.html").Parse(errorTmpl))
}
