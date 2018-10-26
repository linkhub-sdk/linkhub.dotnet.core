using System.Collections.Generic;
using System.Runtime.Serialization;

namespace Linkhub
{
    [DataContract]
    public class Token
    {
        private string _session_token;
        private string _serviceID;
        private string _linkID;
        private string _usercode;
        private string _ipaddress;
        private string _expiration;
        private List<string> _scope;

        [DataMember]
        public string session_token
        {
            get { return _session_token; }
            set { _session_token = value; }
        }

        [DataMember]
        public string serviceID
        {
            get { return _serviceID; }
            set { _serviceID = value; }
        }

        [DataMember]
        public string linkID
        {
            get { return _linkID; }
            set { _linkID = value; }
        }

        [DataMember]
        public string usercode
        {
            get { return _usercode; }
            set { _usercode = value; }
        }

        [DataMember]
        public string expiration
        {
            get { return _expiration; }
            set { _expiration = value; }
        }

        [DataMember]
        public string ipaddress
        {
            get { return _ipaddress; }
            set { _ipaddress = value; }
        }

        [DataMember]
        public List<string> scope
        {
            get { return _scope; }
            set { _scope = value; }
        }
    }
}