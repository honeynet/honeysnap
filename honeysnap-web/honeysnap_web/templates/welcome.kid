<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'master.kid'">

<head>
    <meta content="text/html; charset=UTF-8" http-equiv="content-type" py:replace="''"/> 
    <title>Honeysnap</title>
</head>

<body>                              
    <div py:if="not tg.identity.anonymous" py:replace="logout()" />
    <div py:replace="mainmenu(request)" />
    
    <h2>Welcome to Honeysnap</h2>
    
    <p>Time is ${now}</p>            
    
    <p>
        Database has ${flows} flows, ${sebek} sebek records and ${irc} irc messages
        from ${honeypots} honeypots
    </p>
    <div py:replace="bottommenu()" />
</body>
</html>
