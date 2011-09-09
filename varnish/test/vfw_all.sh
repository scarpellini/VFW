# Empty UA
curl -H 'User-Agent:'  'http://ec2-50-19-46-43.compute-1.amazonaws.com/politica/1237583227176.html'

# SSI Injection
curl  -X POST -d 'in=<!--#exec' 'http://ec2-50-19-46-43.compute-1.amazonaws.com/politica/1237583227176.html'

# Stored XSS
curl -X POST -d 'in=<script>javascript.alter('xss');</script>' 'http://ec2-50-19-46-43.compute-1.amazonaws.com/politica/1237583227176.html'

# Reflected XSS
curl -X GET 'http://ec2-50-19-46-43.compute-1.amazonaws.com/politica/1237583227176.html?in=<script>javascript.alter('xss');</script>'

# SQL Injection
curl -X GET 'http://ec2-50-19-46-43.compute-1.amazonaws.com/politica/1237583227176.html?in=SELECT * FROM'
