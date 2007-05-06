<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-
transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'master.kid'">

<head>
    <LINK MEDIA="all" HREF="/static/css/details_common.css" TYPE="text/css" REL="stylesheet" />
    <title>Honeysnap</title>
</head>

<body>


<div py:if="not tg.identity.anonymous" py:replace="logout()" />
<div py:replace="mainmenu(request)" />
<div py:replace="search_menu(action='details')"/>
          
<div py:if="len>0">        
    <span py:replace="list(messages)"/>
</div>           
<div py:if="len==0">   
    <p>
    No matching data in database
    </p>        
</div>    
          
<div py:replace="bottommenu()" />
</body>
</html>
