/*
 * =================================================================================
 * Unit for develop interoperation with Linkhub APIs.
 * Functionalities are authentication for Linkhub api products, and to support
 * several base infomation(ex. Remain point).
 *
 * This library coded with .NetCore 2.0, To Process JSON and HMACSHA256.
 * If you need any other version of framework, plz contact with below. 
 * 
 * http://www.linkhub.co.kr
 * Author : LInkhub Dev (code@linkhub.com)
 * Written : 2018-10-25
 * Updated : 2023-11-01
 * Thanks for your interest.
 *
 * Update Log
 * - 2023/08/31 AuthURL Setter added
 * =================================================================================
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;

namespace Linkhub
{
    public class Authority
    {
        private const string APIVersion = "2.0";
        private const string ServiceURL_REAL = "https://auth.linkhub.co.kr";
        private const string ServiceURL_REAL_Static = "https://static-auth.linkhub.co.kr";
        private const string ServiceURL_REAL_GA = "https://ga-auth.linkhub.co.kr";
        private string _LinkID;
        private string _SecretKey;
        private string _AuthURL;

        private bool _ProxyYN;
        private string _ProxyAddress;
        private string _ProxyUserName;
        private string _ProxyPassword;

        public string AuthURL
        {
            set { _AuthURL = value; }
            get { return _AuthURL; }
        }

        public Authority(string LinkID, string SecretKey)
        {
            if (string.IsNullOrEmpty(LinkID)) throw new LinkhubException(-99999999, "LinkID is Not entered");
            if (string.IsNullOrEmpty(SecretKey)) throw new LinkhubException(-99999999, "SecretKey is Not entered");

            this._LinkID = LinkID;
            this._SecretKey = SecretKey;
            this._ProxyYN = false;
        }

        public Authority(string LinkID, string SecretKey, bool ProxyYN, string ProxyAddress, string ProxyUserName, string ProxyPassword)
        {
            if (string.IsNullOrEmpty(LinkID)) throw new LinkhubException(-99999999, "NO LinkID");
            if (string.IsNullOrEmpty(SecretKey)) throw new LinkhubException(-99999999, "NO SecretKey");

            this._LinkID = LinkID;
            this._SecretKey = SecretKey;
            this._ProxyYN = ProxyYN;
            this._ProxyAddress = ProxyAddress;
            this._ProxyUserName = ProxyUserName;
            this._ProxyPassword = ProxyPassword;
        }

        public string getTime()
        {
            return getTime(false, true, false);
        }
        public string getTime(bool UseStaticIP, bool UseLocalTimeYN)
        {
            return getTime(UseStaticIP, UseLocalTimeYN, false);
        }
        public string getTime(bool UseStaticIP, bool UseLocalTimeYN, bool UseGAIP)
        {
            if (UseLocalTimeYN)
            {
                DateTime localTime = DateTime.UtcNow;

                return localTime.ToString("yyyy-MM-ddTHH:mm:ssZ");

            }
            else
            {
                string URI = getTargetURL(UseStaticIP, UseGAIP) + "/Time";

                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(URI);
                request.Timeout = 180000;

                if (this._ProxyYN == true)
                {
                    WebProxy proxyRequest = new WebProxy();

                    Uri proxyURI = new Uri(this._ProxyAddress);
                    proxyRequest.Address = proxyURI;
                    proxyRequest.Credentials = new NetworkCredential(this._ProxyUserName, this._ProxyPassword);
                    request.Proxy = proxyRequest;
                }

                request.Method = "GET";

                try
                {
                    HttpWebResponse response = (HttpWebResponse)request.GetResponse();

                    using (Stream stream = response.GetResponseStream())
                    {
                        StreamReader reader = new StreamReader(stream, Encoding.UTF8);

                        return reader.ReadToEnd();
                    }
                }
                catch (WebException we)
                {
                    if (we.Response != null)
                    {
                        Stream stReadData = we.Response.GetResponseStream();
                        DataContractJsonSerializer ser2 = new DataContractJsonSerializer(typeof(Error));
                        Error t = (Error)ser2.ReadObject(stReadData);

                        throw new LinkhubException(t.code, t.message);
                    }

                    throw new LinkhubException(-99999999, we.Message);
                }
            }

        }

        public Token getToken(string ServiceID, string access_id, List<string> scope, string ForwardIP = null)
        {
            return getToken(ServiceID, access_id, scope, null, false, true, false);
        }

        public Token getToken(string ServiceID, string access_id, List<string> scope, string ForwardIP = null, bool UseStaticIP = false, bool UseLocalTimeYN = true)
        {
            return getToken(ServiceID, access_id, scope, null, false, true, false);
        }

        public Token getToken(string ServiceID, string access_id, List<string> scope, string ForwardIP = null, bool UseStaticIP = false, bool UseLocalTimeYN = true, bool UseGAIP = false)
        {
            if (string.IsNullOrEmpty(ServiceID)) throw new LinkhubException(-99999999, "ServiceID is Not entered");

            Token result = new Token();

            string URI = getTargetURL(UseStaticIP, UseGAIP) + "/" + ServiceID + "/Token";

            string xDate = getTime(UseStaticIP, UseLocalTimeYN, UseGAIP);

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(URI);
            request.Timeout = 180000;

            if (this._ProxyYN == true)
            {
                WebProxy proxyRequest = new WebProxy();

                Uri proxyURI = new Uri(this._ProxyAddress);
                proxyRequest.Address = proxyURI;
                proxyRequest.Credentials = new NetworkCredential(this._ProxyUserName, this._ProxyPassword);
                request.Proxy = proxyRequest;
            }

            request.Headers.Add("x-lh-date", xDate);

            request.Headers.Add("x-lh-version", APIVersion);

            if (ForwardIP != null) request.Headers.Add("x-lh-forwarded", ForwardIP);

            TokenRequest _TR = new TokenRequest();

            _TR.access_id = access_id;
            _TR.scope = scope;

            string postData = "";

            using (MemoryStream ms = new MemoryStream())
            {
                DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(TokenRequest));
                ser.WriteObject(ms, _TR);
                ms.Seek(0, SeekOrigin.Begin);
                postData = new StreamReader(ms).ReadToEnd();
            }

            string HMAC_target = "POST\n";
            HMAC_target += Convert.ToBase64String(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(postData))) + "\n";
            HMAC_target += xDate + "\n";
            if (ForwardIP != null) HMAC_target += ForwardIP + "\n";
            HMAC_target += APIVersion + "\n";
            HMAC_target += "/" + ServiceID + "/Token";

            HMACSHA256 hmac = new HMACSHA256(Convert.FromBase64String(_SecretKey));
            string bearerToken = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(HMAC_target)));

            request.Headers.Add("Authorization", "LINKHUB" + " " + _LinkID + " " + bearerToken);

            request.Headers.Add("User-Agent", "DOTNETCORE LINKHUB SDK");

            request.Method = "POST";

            byte[] btPostDAta = Encoding.UTF8.GetBytes(postData);

            request.ContentLength = btPostDAta.Length;

            request.GetRequestStream().Write(btPostDAta, 0, btPostDAta.Length);

            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                Stream stReadData = response.GetResponseStream();
                DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(Token));

                result = (Token)ser.ReadObject(stReadData);
            }
            catch (Exception we)
            {
                if (we is WebException && ((WebException)we).Response != null)
                {
                    Stream stReadData = ((WebException)we).Response.GetResponseStream();
                    DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(Error));
                    Error t = (Error)ser.ReadObject(stReadData);

                    throw new LinkhubException(t.code, t.message);
                }

                throw new LinkhubException(-99999999, we.Message);
            }

            return result;
        }

        public double getBalance(string BearerToken, string ServiceID)
        {
            return getBalance(BearerToken, ServiceID, false, false);
        }
        public double getBalance(string BearerToken, string ServiceID, bool UseStaticIP)
        {
            return getBalance(BearerToken, ServiceID, false, false);
        }
        //연동회원 잔여포인트 확인
        public double getBalance(string BearerToken, string ServiceID, bool UseStaticIP, bool UseGAIP)
        {
            if (string.IsNullOrEmpty(ServiceID)) throw new LinkhubException(-99999999, "ServiceID is Not entered");
            if (string.IsNullOrEmpty(BearerToken)) throw new LinkhubException(-99999999, "BearerToken is Not entered");

            string URI = getTargetURL(UseStaticIP, UseGAIP) + "/" + ServiceID + "/Point";
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(URI);
            request.Timeout = 180000;

            if (this._ProxyYN == true)
            {
                WebProxy proxyRequest = new WebProxy();

                Uri proxyURI = new Uri(this._ProxyAddress);
                proxyRequest.Address = proxyURI;
                proxyRequest.Credentials = new NetworkCredential(this._ProxyUserName, this._ProxyPassword);
                request.Proxy = proxyRequest;
            }

            request.Headers.Add("Authorization", "Bearer" + " " + BearerToken);

            request.Headers.Add("User-Agent", "DOTNETCORE LINKHUB SDK");

            request.Method = "GET";

            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                Stream stReadData = response.GetResponseStream();
                DataContractJsonSerializer ser2 = new DataContractJsonSerializer(typeof(PointResult));
                PointResult result = (PointResult)ser2.ReadObject(stReadData);

                return result.remainPoint;
            }
            catch (WebException we)
            {
                if (we.Response != null)
                {
                    Stream stReadData = we.Response.GetResponseStream();
                    DataContractJsonSerializer ser2 = new DataContractJsonSerializer(typeof(Error));
                    Error t = (Error)ser2.ReadObject(stReadData);

                    throw new LinkhubException(t.code, t.message);
                }

                throw new LinkhubException(-99999999, we.Message);
            }
        }

        public double getPartnerBalance(string BearerToken, string ServiceID)
        {
            return getPartnerBalance(BearerToken, ServiceID, false, false);
        }
        public double getPartnerBalance(string BearerToken, string ServiceID, bool UseStaticIP)
        {
            return getPartnerBalance(BearerToken, ServiceID, false, false);
        }
        //파트너 잔여포인트 확인
        public double getPartnerBalance(string BearerToken, string ServiceID, bool UseStaticIP, bool UseGAIP)
        {
            if (string.IsNullOrEmpty(ServiceID)) throw new LinkhubException(-99999999, "ServiceID is Not entered");
            if (string.IsNullOrEmpty(BearerToken)) throw new LinkhubException(-99999999, "BearerToken is Not entered");

            string URI = getTargetURL(UseStaticIP, UseGAIP) + "/" + ServiceID + "/PartnerPoint";
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(URI);
            request.Timeout = 180000;

            if (this._ProxyYN == true)
            {
                WebProxy proxyRequest = new WebProxy();

                Uri proxyURI = new Uri(this._ProxyAddress);
                proxyRequest.Address = proxyURI;
                proxyRequest.Credentials = new NetworkCredential(this._ProxyUserName, this._ProxyPassword);
                request.Proxy = proxyRequest;
            }

            request.Headers.Add("Authorization", "Bearer" + " " + BearerToken);

            request.Headers.Add("User-Agent", "DOTNETCORE LINKHUB SDK");

            request.Method = "GET";

            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                Stream stReadData = response.GetResponseStream();
                DataContractJsonSerializer ser2 = new DataContractJsonSerializer(typeof(PointResult));
                PointResult result = (PointResult)ser2.ReadObject(stReadData);

                return result.remainPoint;
            }
            catch (WebException we)
            {
                if (we.Response != null)
                {
                    Stream stReadData = we.Response.GetResponseStream();
                    DataContractJsonSerializer ser2 = new DataContractJsonSerializer(typeof(Error));
                    Error t = (Error)ser2.ReadObject(stReadData);
                    throw new LinkhubException(t.code, t.message);
                }

                throw new LinkhubException(-99999999, we.Message);
            }
        }

        public string getPartnerURL(string BearerToken, string ServiceID, string TOGO)
        {
            return getPartnerURL(BearerToken, ServiceID, TOGO, false, false);
        }
        public string getPartnerURL(string BearerToken, string ServiceID, string TOGO, bool UseStaticIP)
        {
            return getPartnerURL(BearerToken, ServiceID, TOGO, false, false);
        }
        //파트너 포인트충전 팝업 URL
        public string getPartnerURL(string BearerToken, string ServiceID, string TOGO, bool UseStaticIP, bool UseGAIP)
        {

            if (string.IsNullOrEmpty(ServiceID)) throw new LinkhubException(-99999999, "ServiceID is Not entered");
            if (string.IsNullOrEmpty(BearerToken)) throw new LinkhubException(-99999999, "BearerToken is Not entered");

            string URI = getTargetURL(UseStaticIP, UseGAIP) + "/" + ServiceID + "/URL?TG=" + TOGO;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(URI);
            request.Timeout = 180000;

            if (this._ProxyYN == true)
            {
                WebProxy proxyRequest = new WebProxy();

                Uri proxyURI = new Uri(this._ProxyAddress);
                proxyRequest.Address = proxyURI;
                proxyRequest.Credentials = new NetworkCredential(this._ProxyUserName, this._ProxyPassword);
                request.Proxy = proxyRequest;
            }


            request.Headers.Add("Authorization", "Bearer" + " " + BearerToken);

            request.Headers.Add("User-Agent", "DOTNETCORE LINKHUB SDK");

            request.Method = "GET";

            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                Stream stReadData = response.GetResponseStream();
                DataContractJsonSerializer ser2 = new DataContractJsonSerializer(typeof(URLResult));
                URLResult result = (URLResult)ser2.ReadObject(stReadData);

                return result.url;
            }
            catch (WebException we)
            {
                if (we.Response != null)
                {
                    Stream stReadData = we.Response.GetResponseStream();
                    DataContractJsonSerializer ser2 = new DataContractJsonSerializer(typeof(Error));
                    Error t = (Error)ser2.ReadObject(stReadData);
                    throw new LinkhubException(t.code, t.message);
                }

                throw new LinkhubException(-99999999, we.Message);
            }
        }

        public MemberPointDetail getBalanceDetail(string BearerToken, string ServiceID, bool UseStaticIP, bool UseGAIP)
        {
            if (string.IsNullOrEmpty(BearerToken)) throw new LinkhubException(-99999999, "BearerToken이 입력되지 않았습니다.");
            if (string.IsNullOrEmpty(ServiceID)) throw new LinkhubException(-99999999, "서비스아이디가 입력되지 않았습니다.");

            string URI = getTargetURL(UseStaticIP, UseGAIP) + "/" + ServiceID + "/TotalPoint";
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(URI);
            request.Timeout = 180000;

            if (this._ProxyYN == true)
            {
                WebProxy proxyRequest = new WebProxy();

                Uri proxyURI = new Uri(this._ProxyAddress);
                proxyRequest.Address = proxyURI;
                proxyRequest.Credentials = new NetworkCredential(this._ProxyUserName, this._ProxyPassword);
                request.Proxy = proxyRequest;
            }

            request.Headers.Add("Authorization", "Bearer" + " " + BearerToken);

            request.Headers.Add("User-Agent", "DOTNETCORE LINKHUB SDK");

            request.Method = "GET";

            try
            {
                MemberPointDetail result = parseResponse<MemberPointDetail>(request);
                return result;
            }
            catch (WebException we)
            {
                if (we.Response != null)
                {
                    Stream stReadData = we.Response.GetResponseStream();
                    DataContractJsonSerializer ser2 = new DataContractJsonSerializer(typeof(Error));
                    Error t = (Error)ser2.ReadObject(stReadData);
                    throw new LinkhubException(t.code, t.message);
                }

                throw new LinkhubException(-99999999, we.Message);
            }
        }

        private string getTargetURL(bool UseStaticIP, bool UseGAIP)
        {
            if (_AuthURL != null)
            {
                return _AuthURL;
            }

            if (UseGAIP)
            {
                return ServiceURL_REAL_GA;
            }
            else if (UseStaticIP)
            {
                return ServiceURL_REAL_Static;
            }
            else
            {
                return ServiceURL_REAL;
            }
        }

        [DataContract]
        private class Error
        {
            [DataMember] public long code { get; set; }
            [DataMember] public string message { get; set; }
        }

        [DataContract]
        private class TokenRequest
        {
            [DataMember] public string access_id { get; set; }
            [DataMember] public List<string> scope { get; set; }
        }

        [DataContract]
        private class PointResult
        {
            [DataMember] public double remainPoint { get; set; }
        }

        [DataContract]
        public class URLResult
        {
            [DataMember] public string url;
        }

        [DataContract]
        public class MemberPointDetail
        {
            [DataMember] public string totalPoint;
            [DataMember] public string chargePoint;
            [DataMember] public string bonusPoint;
        }

        private T parseResponse<T>(HttpWebRequest request)
        {
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            Stream stReadData = response.GetResponseStream();
            DataContractJsonSerializer ser2 = new DataContractJsonSerializer(typeof(T));
            T result = (T)ser2.ReadObject(stReadData);
            return result;
        }
    }
}