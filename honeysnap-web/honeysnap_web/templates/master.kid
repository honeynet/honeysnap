<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<?python import sitetemplate ?>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#" py:extends="sitetemplate">

<head py:match="item.tag=='{http://www.w3.org/1999/xhtml}head'" py:attrs="item.items()">
    <meta content="text/html; charset=iso-8859-1" http-equiv="content-type" py:replace="''"/> >
    <LINK MEDIA="all" HREF="/static/css/master.css" TYPE="text/css" REL="stylesheet" />
    <title py:replace="''">Your title goes here</title>
    <meta py:replace="item[:]"/>  
	<script type="text/javascript" src="/static/javascript/common.js" />
</head>

<body py:match="item.tag=='{http://www.w3.org/1999/xhtml}body'" py:attrs="item.items()">
    <div py:if="tg.config('identity.on',False) and not 'logging_in' in locals()" id="pageLogin">
        <span py:if="tg.identity.anonymous">
            <a href="/login">Login</a>
        </span>
    </div>
    <div id="logout" py:def="logout()">
      <a href="/logout"> (Logout ${tg.identity.user.displayName})</a>
    </div>

    <div id="menu" py:def="mainmenu(request)">
        <div py:if="request"> 
            <a href="${tg.url('/', request)}"> Summary </a> |
            <a href="${tg.url('/flows/details', request)}"> Flow Details </a>  |
            <a href="${tg.url('/sebek/details', request)}"> Sebek Details </a> |
            <a href="${tg.url('/irc/summary', request)}"> IRC Summary </a>| 
            <a href="${tg.url('/irc/details', request)}"> IRC Details </a>| 
            <a href="${tg.url('/ip/summary', request)}">  IP Summary </a>|
            <a href="${tg.url('/ip', request)}">IP Lookup </a>| 
        </div>
        <div py:if="not request">
            <a href="${tg.url('/', request)}"> Summary </a> |
            <a href="${tg.url('/flows/details', request)}"> Flow Details </a> |
            <a href="${tg.url('/sebek/details', request)}"> Sebek Details </a> |
            <a href="${tg.url('/irc/summary')}"> IRC Summary </a>| 
            <a href="${tg.url('/irc/details')}"> IRC Details </a>| 
            <a href="${tg.url('/ip/summary')}">  IP Summary </a>|
            <a href="${tg.url('/ip')}">IP Lookup </a>| 
        </div>
    </div>

    <div py:def="search_menu(action)">
      <div id="searchform" class="invisible" align="center">
    ${form(action=action)}
      </div>
      <div id="searchtab" class="searchtab">
        <a href="#" onclick="toggleVisible('searchform'); toggleVisible('searchtab'); toggleVisible('hidetab')"> Detailed Search </a>
      </div>
      <div id="hidetab" class="invisible" align="center">
        <a href="#" onclick="toggleVisible('searchform'); toggleVisible('searchtab'); toggleVisible('hidetab')"> Hide Search Form </a>
      </div>
    </div>

    <div id="bottommenu" py:def="bottommenu()">
      <a href="${tg.url('/')}"> Clear Search </a>
    </div>

    <div py:replace="item[:]"/>

</body>

</html>
