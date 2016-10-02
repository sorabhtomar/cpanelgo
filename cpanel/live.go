package cpanel

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"log"
	"os"

	"github.com/letsencrypt-cpanel/cpanelgo"
)

type LiveApiGateway struct {
	net.Conn
}

func NewLiveApi(network, address string) (CpanelApi, error) {
	c := &LiveApiGateway{}

	conn, err := net.Dial(network, address)
	if err != nil {
		return CpanelApi{}, err
	}
	c.Conn = conn

	if err := c.exec(`<cpaneljson enable="1">`, nil); err != nil {
		return CpanelApi{}, fmt.Errorf("Enabling JSON: %v", err)
	}

	return CpanelApi{cpanelgo.NewApi(c)}, nil
}

func (c *LiveApiGateway) UAPI(module, function string, arguments cpanelgo.Args, out interface{}) error {
	req := CpanelApiRequest{
		RequestType: "exec",
		ApiVersion:  "uapi",
		Module:      module,
		Function:    function,
		Arguments:   arguments,
	}

	return c.api(req, out)
}

func (c *LiveApiGateway) API2(module, function string, arguments cpanelgo.Args, out interface{}) error {
	req := CpanelApiRequest{
		RequestType: "exec",
		ApiVersion:  "2",
		Module:      module,
		Function:    function,
		Arguments:   arguments,
	}

	return c.api(req, out)
}

func (c *LiveApiGateway) API1(module, function string, arguments []string, out interface{}) error {
	req := map[string]interface{}{
		"module":     module,
		"reqtype":    "exec",
		"func":       function,
		"apiversion": "1",
		"args":       arguments,
	}
	bytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	return c.exec("<cpanelaction>"+string(bytes)+"</cpanelaction>", out)
}

func (c *LiveApiGateway) Close() error {
	return c.Conn.Close()
}

func (c *LiveApiGateway) api(req CpanelApiRequest, out interface{}) error {
	buf, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if os.Getenv("DEBUG_CPANEL_RESPONSES") == "1" {
		log.Println("[Lets Encrypt for cPanel] Request: ", string(buf))
	}
	switch req.ApiVersion {
	case "uapi":
		var result cpanelgo.UAPIResult
		err := c.exec("<cpanelaction>"+string(buf)+"</cpanelaction>", &result)
		if err == nil {
			err = result.Error()
		}
		if err != nil {
			return err
		}

		if os.Getenv("DEBUG_CPANEL_RESPONSES") == "1" {
			log.Println("[Lets Encrypt for cPanel] UResult: ", string(result.Result))
		}
		/*if req.Function == "domains_data" {
			return json.Unmarshal([]byte(badData), out)
		}*/
		return json.Unmarshal(result.Result, out)
	case "2":
		var result cpanelgo.API2Result
		err := c.exec("<cpanelaction>"+string(buf)+"</cpanelaction>", &result)
		if err == nil {
			err = result.Error()
		}
		if err != nil {
			return err
		}
		if os.Getenv("DEBUG_CPANEL_RESPONSES") == "1" {
			log.Println("[Lets Encrypt for cPanel] 2Result: ", string(result.Result))
		}
		return json.Unmarshal(result.Result, out)
	default:
		return c.exec("<cpanelaction>"+string(buf)+"</cpanelaction>", out)
	}
}

//var badData = `{"errors":null,"status":1,"messages":null,"metadata":{},"data":{"sub_domains":[0,{"type":"sub_domain","user":"pdreseller","group":"pdreseller","serveralias":"www.test.reseller.plugindev.id-rsa.pub","homedir":"/home/pdreseller","domain":"test.reseller.plugindev.id-rsa.pub","documentroot":"/home/pdreseller/test.reseller.plugindev.id-rsa.pub","owner":"root","servername":"test.reseller.plugindev.id-rsa.pub","userdirprotect":"","serveradmin":"webmaster@test.reseller.plugindev.id-rsa.pub","ip":"111.223.237.237","ipv6":null,"hascgi":"1","no_cache_update":"0","usecanonicalname":"Off","phpopenbasedirprotect":"1"}],"addon_domains":[{"customlog":[{"target":"/usr/local/apache/domlogs/reseller-addon.reseller.plugindev.id-rsa.pub","format":"combined"},{"format":"combined","target":"/etc/apache2/logs/domlogs/reseller-addon.reseller.plugindev.id-rsa.pub"}],"type":"addon_domain","group":"pdreseller","user":"pdreseller","ifmoduleincludemodule":{"directoryhomepdresellerpublichtmlreselleraddonplugindevidrsapub":{"ssilegacyexprparser":[{"value":" On"}]}},"serveralias":"www.reseller-addon.reseller.plugindev.id-rsa.pub www.reseller-addon.plugindev.id-rsa.pub reseller-addon.plugindev.id-rsa.pub","ifmodulelogconfigmodule":{"ifmodulelogiomodule":{"customlog":[{"format":"\"%{%s}t %I .\\n%{%s}t %O .\"","target":"/usr/local/apache/domlogs/reseller-addon.reseller.plugindev.id-rsa.pub-bytes_log"}]}},"homedir":"/home/pdreseller","ifmodulealiasmodule":{"scriptalias":[{"path":"/home/pdreseller/public_html/reseller-addon.plugindev.id-rsa.pub/cgi-bin/","url":"/cgi-bin/"}]},"documentroot":"/home/pdreseller/public_html/reseller-addon.plugindev.id-rsa.pub","domain":"reseller-addon.plugindev.id-rsa.pub","owner":"root","servername":"reseller-addon.reseller.plugindev.id-rsa.pub","userdirprotect":"","ip":"111.223.237.237","serveradmin":"webmaster@reseller-addon.reseller.plugindev.id-rsa.pub","ipv6":null,"is_addon":"1","hascgi":"1","no_cache_update":"0","port":"80","ifmoduleuserdirmodule":{"ifmodulempmitkc":{"ifmoduleruidmodule":{}}},"usecanonicalname":"Off","ssl":"1","phpopenbasedirprotect":1}],"parked_domains":[],"main_domain":{"userdirprotect":"","servername":"reseller.plugindev.id-rsa.pub","owner":"root","domain":"reseller.plugindev.id-rsa.pub","documentroot":"/home/pdreseller/public_html","homedir":"/home/pdreseller","ifmodulealiasmodule":{"scriptalias":[{"path":"/home/pdreseller/public_html/cgi-bin/","url":"/cgi-bin/"}]},"ifmodulelogconfigmodule":{"ifmodulelogiomodule":{"customlog":[{"format":"\"%{%s}t %I .\\n%{%s}t %O .\"","target":"/usr/local/apache/domlogs/reseller.plugindev.id-rsa.pub-bytes_log"}]}},"serveralias":"www.reseller.plugindev.id-rsa.pub","group":"pdreseller","type":"main_domain","user":"pdreseller","ifmoduleincludemodule":{"directoryhomepdresellerpublichtml":{"ssilegacyexprparser":[{"value":" On"}]}},"customlog":[{"target":"/usr/local/apache/domlogs/reseller.plugindev.id-rsa.pub","format":"combined"},{"target":"/usr/local/apache/domlogs/reseller.plugindev.id-rsa.pub-bytes_log","format":"\"%{%s}t %I .\\n%{%s}t %O .\""},{"target":"/etc/apache2/logs/domlogs/reseller.plugindev.id-rsa.pub","format":"combined"}],"phpopenbasedirprotect":1,"usecanonicalname":"Off","scriptalias":[{"url":"/cgi-bin/","path":"/home/pdreseller/public_html/cgi-bin"}],"ifmoduleuserdirmodule":{"ifmodulempmitkc":{"ifmoduleruidmodule":{}}},"port":"80","hascgi":"1","ip":"111.223.237.237","serveradmin":"webmaster@reseller.plugindev.id-rsa.pub"}}}`

func endsWith(where []byte, what string) bool {
	n := 0
	i := len(where) - len(what)
	if i < 0 {
		return false
	}
	for ; i >= 0 && i < len(where); i++ {
		if where[i] != what[n] {
			return false
		}
		n++
	}
	return true
}

func (c *LiveApiGateway) exec(req string, out interface{}) error {
	if _, err := fmt.Fprintf(c, "%d\n%s", len(req), req); err != nil {
		return err
	}

	var read bytes.Buffer
	rd := bufio.NewReader(c)

	line, _, err := rd.ReadLine() // ignore isprefix
	for err == nil {
		read.Write(line)

		if endsWith(read.Bytes(), "</cpanelresult>") {
			break
		}

		// limit memory footprint of any api response
		if read.Len() >= cpanelgo.ResponseSizeLimit {
			return errors.New("Exceeded maximum API response size")
		}
		line, _, err = rd.ReadLine()
	}
	if err != nil && err != io.EOF {
		return err
	}

	readStr := read.String()

	if n := strings.Index(readStr, "<cpanelresult>{"); n != -1 {
		asJson := readStr[strings.Index(readStr, "<cpanelresult>")+14:]
		asJson = asJson[:strings.LastIndex(asJson, "</cpanelresult>")]

		if out != nil {
			return json.Unmarshal([]byte(asJson), out)
		} else {
			return nil
		}
	}

	return fmt.Errorf("Failed to unmarshal LiveAPI response: %v", readStr)
}
