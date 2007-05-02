<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://purl.org/kid/ns#"
    py:extends="'master.kid'">

<head>
    <meta content="text/html; charset=UTF-8" http-equiv="content-type" py:replace="''"/>
    <title>HoneyMine</title>
</head>

<body>
<?python
   import cherrypy
   request = cherrypy.request.params
   del request['ipaddr']
?>

<div py:if="not tg.identity.anonymous" py:replace="logout()" />
<div py:replace="mainmenu(request)" />

  <table py:def="display_os(array)" border="1">
    <tr>
      <th>OS</th><th>Firstseen</th><th>Lastseen</th>
    </tr>
    <tr py:for="row in array">
      <td py:content="row['os']" />
      <td py:content="row['firstseen']" />
      <td py:content="row['lastseen']" />
    </tr>
  </table>
  <table py:def="display_dict(dict)" border="1">
    <tr py:for="key, value in dict.items()">
      <td py:content="key.title()" />
      <td py:content="value" />
    </tr>
  </table>

  <h2>Search Results. <div py:replace="ipaddr" py:if="ipaddr != None">ipaddr goes here</div></h2>
  
  <p py:if="ipaddr == None">
    IP not found in database
  </p>
  <p py:if="ipaddr != None">
    <div> IP first seen <div py:replace="firstseen"> timedate here</div>,
      last seen <div py:replace="lastseen"> timedate here</div>
    </div>     
  </p>
  <h3 py:if="os != None">OS Details</h3>
  <p  py:if="os != None">
    <div py:replace="display_os(os)">
      Os table replaces this text
    </div>
  </p>
  <h3 py:if="location != None">Location Details</h3>
  <p py:if="location != None">
    <div py:replace="display_dict(location)">
      location table goes here
    </div>
  </p>
  <!---
  <p py:if="location != None">
    <img src="https://88.96.22.252/ip2location/map.php?long=${location['longitude']}&amp;lat=${location['latitude']}&amp;map=512" />
  </p>
  -->
  <div py:replace="bottommenu()" />
</body>
</html>
