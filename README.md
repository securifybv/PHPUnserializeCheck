# PHP Unserialize Check (Burp Scanner Extensions)

This Burp Scanner Extension tries to find PHP Object Injection Vulnerabilities.

It passes a serialized `PDO` object to the found injection points. If PHP tries to unserialize this object a fatal exception is thrown triggered in the object's `__wakeup()` method (ext/pdo/pdo_dbh.c):
```
static PHP_METHOD(PDO, __wakeup)
{
zend_throw_exception_ex(php_pdo_get_exception(), 0, "You cannot serialize or unserialize PDO instances");
}
```
If `display_errors` is disabled, this will result in a 500 Internal Server Error. If this is the case the check will try to unserialize a stdClass object and an empty array. If either one returns a 200 OK, it is assumed that the code is vulnerable to PHP Object Injection.

If `display_errors` is enabled, the fatal exception is returned to the user, making it easier to detected the vulnerability.

Based on http://blog.portswigger.net/2012/12/sample-burp-suite-extension-custom_20.html

![alt tag](https://raw.githubusercontent.com/securifybv/PHPUnserializeCheck/master/img/example%20report.png)
