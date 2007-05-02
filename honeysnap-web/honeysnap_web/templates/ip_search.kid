<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'master.kid'">

<head>
    <meta content="text/html; charset=UTF-8" http-equiv="content-type" py:replace="''"/>
    <title>IP Address Search</title>
</head>

<body>

<?python
  import cherrypy
  request = cherrypy.request.params
?>

<div py:if="not tg.identity.anonymous" py:replace="logout()" />
<div py:replace="mainmenu(request)" />

  <p>Enter an address to search for</p>
  <p>${ip_search_form(action=tg.url('by_ip', request))}</p>
  <div py:replace="bottommenu()" />
</body>
</html>
