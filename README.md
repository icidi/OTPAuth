# OTPAuth

A simple authentication (Forward Auth) gateway utilizing OTP as 1FA.

Tested with Caddy and should work with other web servers like Nginx.

Requires Python >= 3.6.

## Use case

Many devices (e.g. home routers) come with their own login pages and they do not integrate well with authentication provided by an upstream proxy.

If you want to expose those login pages to the Internet and consider securing them with 2FA, a single OTP is enough because you still need to enter the credentials on the login pages.

```
     Internet
        ^
        |
        v
-----------------
|  Web Server   | <--> OTPAuth as 1st Factor
|(Reverse Proxy)| <--> Your Devices whose Login Credentials as 2nd Factor
-----------------

```

I did not find any solution that allows OTP as 1FA, which means I have to enter the username and password first, then OTP, then username and password again for the device.

The password in the first step is redundant and OTPAuth requires username and OTP in the first step, instead of password-then-OTP.