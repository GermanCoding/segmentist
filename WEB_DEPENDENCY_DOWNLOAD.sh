#!/bin/bash
version_bootstrap=1.1.3
version_jquery=3.6.0
wget -P ./web/css/ https://cdn.jsdelivr.net/npm/bootstrap-dark-5@$version_bootstrap/dist/css/bootstrap-dark.min.css
wget -P ./web/css/ https://cdn.jsdelivr.net/npm/bootstrap-dark-5@$version_bootstrap/dist/css/bootstrap-dark.css.map
wget -P ./web/css/ https://cdn.jsdelivr.net/npm/bootstrap-dark-5@$version_bootstrap/dist/css/bootstrap-dark.css
wget -P ./web/js/ https://code.jquery.com/jquery-$version_jquery.min.js
wget -P ./web/js/ https://code.jquery.com/jquery-$version_jquery.js
wget -P ./web/js/  https://code.jquery.com/jquery-$version_jquery.min.map
