# Fabrick_test

usage: fabrick_test <address> <port> <doc_root>
Example:fabrick_test 0.0.0.0 8080


Invoke method1:
http://localhost:8080/accounts/1/balance

Invoke method2:
http://localhost:8080/accounts/1/payments/sct/orders

it can also handle static asset file from docroot
example:
http://localhost:8080/index.html
http://localhost:8080/photo.png


it require boost Libraries and openssl in order to compile!
