Security of Systems-n-Services (2024-2025)

Assignment04
Students: Asterinos Karalis 2020030107  - Zografoula Ioanna Neamonitaki 2020030088

Firstly setup the page locally as described below

1. Download the .zip file, extract its contents and `cd public/`.
2. You will need to have Python3 installed in your system.
3. Run `python3 -m pip install -r requirements.txt`.
4. Run `./run.sh`.
5. The application will be running under `http://127.0.0.1:8080`.

 
1. Bypass the Login Page (SQL Injection)

1) Open the application.
2) On the login page, enter the following "' OR 1=1 --" in the password field and click login

This SQL injection exploits the flawed query. By injecting OR 1=1, we always make the condition true, bypassing password validation.


2. Exploit DOM-XSS

The DOM-XSS vulnerability is in the greet.js file which reads the URL hash and directly writes it into the HTML using document.write().
This allows JavaScript code to be injected.

1) Navigate to http://127.0.0.1:8080/dashboard.
2) Type the following "http://127.0.0.1:8080/dashboard#user%3Cscript%3Ealert(1)%3C/script%3E" and press Enter.

The <script> tag is injected into the DOM without sanitization which causes an alert to be executed.

3. Exploit Reflected XSS

The flash messages on the site are vulnerable to reflected XSS, specifically in the search functionality.

1) Navigate to  http://127.0.0.1:8080/dashboard and use the search form.
2) Submit the following "<svg onload=alert(1)>" as the search term and click "Search".

This XSS payload is reflected in the flash message due to improper output encoding which triggers the alert message.

4. SQL Injection in Search

The /search endpoint is vulnerable to SQL injection. This can be exploited to extract data from the database.

1) Navigate to  http://127.0.0.1:8080/dashboard.
2) In the search field, enter the following "' UNION SELECT username, password, 1 FROM users--" to extract the users table information (admin password).

This payload exploits the SQL query. By injecting a UNION query, you can retrieve the username and password fields from the users table.

5. Login as Admin

Once you retrieve the superadmin password from the SQL injection in Task 4, you can log in as the admin.

1) Navigate to http://127.0.0.1:8080/admin.
2) Enter the superadmin password that you retrieved into the form and submit it.


6. Exploit Open Redirect

The goto route is vulnerable to an open redirect. We can redirect users to arbitrary websites by modifying the to parameter.

1) We simple navigate using URL like this example: http://127.0.0.1:8080/go?to=http://oracle.com

This will redirect the user to http://oracle.com due to the unsanitized input being used in the redirect() function.


7. Exploit Local File Inclusion (LFI)

The /admin route has a potential LFI vulnerability due to the file inclusion mechanism not handling directory traversal properly.

1)Navigate to http://127.0.0.1:8080/admin.
2)In the filename field, use "http://127.0.0.1:8080/admin?show=../../../../etc/passwd" to attempt reading a sensitive file:

The URL attempts to traverse the directory and access /etc/passwd. 
If the server permits file traversal and does not sanitize file paths properly, it will return the file contents.
