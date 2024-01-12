﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace ServiceReferenceRemoteSignature
{
    using System.Runtime.Serialization;
    
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.3")]
    [System.Runtime.Serialization.DataContractAttribute(Name="HashAlgorithm", Namespace="http://ca.t4trust.ae/RemoteSigner/")]
    public enum HashAlgorithm : int
    {
        
        [System.Runtime.Serialization.EnumMemberAttribute()]
        SHA1 = 0,
        
        [System.Runtime.Serialization.EnumMemberAttribute()]
        SHA256 = 1,
        
        [System.Runtime.Serialization.EnumMemberAttribute()]
        SHA384 = 2,
        
        [System.Runtime.Serialization.EnumMemberAttribute()]
        SHA512 = 3,
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.3")]
    [System.ServiceModel.ServiceContractAttribute(Namespace="http://ca.t4trust.ae/RemoteSigner/", ConfigurationName="ServiceReferenceRemoteSignature.RemoteSignatureSoap")]
    public interface RemoteSignatureSoap
    {
        
        // CODEGEN: Generating message contract since element name GetSigningCertificateResult from namespace http://ca.t4trust.ae/RemoteSigner/ is not marked nillable
        [System.ServiceModel.OperationContractAttribute(Action="http://ca.t4trust.ae/RemoteSigner/GetSigningCertificate", ReplyAction="*")]
        ServiceReferenceRemoteSignature.GetSigningCertificateResponse GetSigningCertificate(ServiceReferenceRemoteSignature.GetSigningCertificateRequest request);
        
        [System.ServiceModel.OperationContractAttribute(Action="http://ca.t4trust.ae/RemoteSigner/GetSigningCertificate", ReplyAction="*")]
        System.Threading.Tasks.Task<ServiceReferenceRemoteSignature.GetSigningCertificateResponse> GetSigningCertificateAsync(ServiceReferenceRemoteSignature.GetSigningCertificateRequest request);
        
        // CODEGEN: Generating message contract since element name hashToSign from namespace http://ca.t4trust.ae/RemoteSigner/ is not marked nillable
        [System.ServiceModel.OperationContractAttribute(Action="http://ca.t4trust.ae/RemoteSigner/RemoteSign", ReplyAction="*")]
        ServiceReferenceRemoteSignature.RemoteSignResponse RemoteSign(ServiceReferenceRemoteSignature.RemoteSignRequest request);
        
        [System.ServiceModel.OperationContractAttribute(Action="http://ca.t4trust.ae/RemoteSigner/RemoteSign", ReplyAction="*")]
        System.Threading.Tasks.Task<ServiceReferenceRemoteSignature.RemoteSignResponse> RemoteSignAsync(ServiceReferenceRemoteSignature.RemoteSignRequest request);
        
        // CODEGEN: Generating message contract since element name hashToSign from namespace http://ca.t4trust.ae/RemoteSigner/ is not marked nillable
        [System.ServiceModel.OperationContractAttribute(Action="http://ca.t4trust.ae/RemoteSigner/RemoteSignWithOid", ReplyAction="*")]
        ServiceReferenceRemoteSignature.RemoteSignWithOidResponse RemoteSignWithOid(ServiceReferenceRemoteSignature.RemoteSignWithOidRequest request);
        
        [System.ServiceModel.OperationContractAttribute(Action="http://ca.t4trust.ae/RemoteSigner/RemoteSignWithOid", ReplyAction="*")]
        System.Threading.Tasks.Task<ServiceReferenceRemoteSignature.RemoteSignWithOidResponse> RemoteSignWithOidAsync(ServiceReferenceRemoteSignature.RemoteSignWithOidRequest request);
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.3")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class GetSigningCertificateRequest
    {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Name="GetSigningCertificate", Namespace="http://ca.t4trust.ae/RemoteSigner/", Order=0)]
        public ServiceReferenceRemoteSignature.GetSigningCertificateRequestBody Body;
        
        public GetSigningCertificateRequest()
        {
        }
        
        public GetSigningCertificateRequest(ServiceReferenceRemoteSignature.GetSigningCertificateRequestBody Body)
        {
            this.Body = Body;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.3")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.Runtime.Serialization.DataContractAttribute()]
    public partial class GetSigningCertificateRequestBody
    {
        
        public GetSigningCertificateRequestBody()
        {
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.3")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class GetSigningCertificateResponse
    {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Name="GetSigningCertificateResponse", Namespace="http://ca.t4trust.ae/RemoteSigner/", Order=0)]
        public ServiceReferenceRemoteSignature.GetSigningCertificateResponseBody Body;
        
        public GetSigningCertificateResponse()
        {
        }
        
        public GetSigningCertificateResponse(ServiceReferenceRemoteSignature.GetSigningCertificateResponseBody Body)
        {
            this.Body = Body;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.3")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.Runtime.Serialization.DataContractAttribute(Namespace="http://ca.t4trust.ae/RemoteSigner/")]
    public partial class GetSigningCertificateResponseBody
    {
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=0)]
        public byte[] GetSigningCertificateResult;
        
        public GetSigningCertificateResponseBody()
        {
        }
        
        public GetSigningCertificateResponseBody(byte[] GetSigningCertificateResult)
        {
            this.GetSigningCertificateResult = GetSigningCertificateResult;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.3")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class RemoteSignRequest
    {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Name="RemoteSign", Namespace="http://ca.t4trust.ae/RemoteSigner/", Order=0)]
        public ServiceReferenceRemoteSignature.RemoteSignRequestBody Body;
        
        public RemoteSignRequest()
        {
        }
        
        public RemoteSignRequest(ServiceReferenceRemoteSignature.RemoteSignRequestBody Body)
        {
            this.Body = Body;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.3")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.Runtime.Serialization.DataContractAttribute(Namespace="http://ca.t4trust.ae/RemoteSigner/")]
    public partial class RemoteSignRequestBody
    {
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=0)]
        public byte[] hashToSign;
        
        [System.Runtime.Serialization.DataMemberAttribute(Order=1)]
        public ServiceReferenceRemoteSignature.HashAlgorithm signatureAlgorithm;
        
        public RemoteSignRequestBody()
        {
        }
        
        public RemoteSignRequestBody(byte[] hashToSign, ServiceReferenceRemoteSignature.HashAlgorithm signatureAlgorithm)
        {
            this.hashToSign = hashToSign;
            this.signatureAlgorithm = signatureAlgorithm;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.3")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class RemoteSignResponse
    {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Name="RemoteSignResponse", Namespace="http://ca.t4trust.ae/RemoteSigner/", Order=0)]
        public ServiceReferenceRemoteSignature.RemoteSignResponseBody Body;
        
        public RemoteSignResponse()
        {
        }
        
        public RemoteSignResponse(ServiceReferenceRemoteSignature.RemoteSignResponseBody Body)
        {
            this.Body = Body;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.3")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.Runtime.Serialization.DataContractAttribute(Namespace="http://ca.t4trust.ae/RemoteSigner/")]
    public partial class RemoteSignResponseBody
    {
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=0)]
        public byte[] RemoteSignResult;
        
        public RemoteSignResponseBody()
        {
        }
        
        public RemoteSignResponseBody(byte[] RemoteSignResult)
        {
            this.RemoteSignResult = RemoteSignResult;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.3")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class RemoteSignWithOidRequest
    {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Name="RemoteSignWithOid", Namespace="http://ca.t4trust.ae/RemoteSigner/", Order=0)]
        public ServiceReferenceRemoteSignature.RemoteSignWithOidRequestBody Body;
        
        public RemoteSignWithOidRequest()
        {
        }
        
        public RemoteSignWithOidRequest(ServiceReferenceRemoteSignature.RemoteSignWithOidRequestBody Body)
        {
            this.Body = Body;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.3")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.Runtime.Serialization.DataContractAttribute(Namespace="http://ca.t4trust.ae/RemoteSigner/")]
    public partial class RemoteSignWithOidRequestBody
    {
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=0)]
        public byte[] hashToSign;
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=1)]
        public string signatureAlgorithmOID;
        
        public RemoteSignWithOidRequestBody()
        {
        }
        
        public RemoteSignWithOidRequestBody(byte[] hashToSign, string signatureAlgorithmOID)
        {
            this.hashToSign = hashToSign;
            this.signatureAlgorithmOID = signatureAlgorithmOID;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.3")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class RemoteSignWithOidResponse
    {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Name="RemoteSignWithOidResponse", Namespace="http://ca.t4trust.ae/RemoteSigner/", Order=0)]
        public ServiceReferenceRemoteSignature.RemoteSignWithOidResponseBody Body;
        
        public RemoteSignWithOidResponse()
        {
        }
        
        public RemoteSignWithOidResponse(ServiceReferenceRemoteSignature.RemoteSignWithOidResponseBody Body)
        {
            this.Body = Body;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.3")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.Runtime.Serialization.DataContractAttribute(Namespace="http://ca.t4trust.ae/RemoteSigner/")]
    public partial class RemoteSignWithOidResponseBody
    {
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=0)]
        public byte[] RemoteSignWithOidResult;
        
        public RemoteSignWithOidResponseBody()
        {
        }
        
        public RemoteSignWithOidResponseBody(byte[] RemoteSignWithOidResult)
        {
            this.RemoteSignWithOidResult = RemoteSignWithOidResult;
        }
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.3")]
    public interface RemoteSignatureSoapChannel : ServiceReferenceRemoteSignature.RemoteSignatureSoap, System.ServiceModel.IClientChannel
    {
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.Tools.ServiceModel.Svcutil", "2.0.3")]
    public partial class RemoteSignatureSoapClient : System.ServiceModel.ClientBase<ServiceReferenceRemoteSignature.RemoteSignatureSoap>, ServiceReferenceRemoteSignature.RemoteSignatureSoap
    {
        
        /// <summary>
        /// Implement this partial method to configure the service endpoint.
        /// </summary>
        /// <param name="serviceEndpoint">The endpoint to configure</param>
        /// <param name="clientCredentials">The client credentials</param>
        static partial void ConfigureEndpoint(System.ServiceModel.Description.ServiceEndpoint serviceEndpoint, System.ServiceModel.Description.ClientCredentials clientCredentials);
        
        public RemoteSignatureSoapClient(EndpointConfiguration endpointConfiguration) : 
                base(RemoteSignatureSoapClient.GetBindingForEndpoint(endpointConfiguration), RemoteSignatureSoapClient.GetEndpointAddress(endpointConfiguration))
        {
            this.Endpoint.Name = endpointConfiguration.ToString();
            ConfigureEndpoint(this.Endpoint, this.ClientCredentials);
        }
        
        public RemoteSignatureSoapClient(EndpointConfiguration endpointConfiguration, string remoteAddress) : 
                base(RemoteSignatureSoapClient.GetBindingForEndpoint(endpointConfiguration), new System.ServiceModel.EndpointAddress(remoteAddress))
        {
            this.Endpoint.Name = endpointConfiguration.ToString();
            ConfigureEndpoint(this.Endpoint, this.ClientCredentials);
        }
        
        public RemoteSignatureSoapClient(EndpointConfiguration endpointConfiguration, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(RemoteSignatureSoapClient.GetBindingForEndpoint(endpointConfiguration), remoteAddress)
        {
            this.Endpoint.Name = endpointConfiguration.ToString();
            ConfigureEndpoint(this.Endpoint, this.ClientCredentials);
        }
        
        public RemoteSignatureSoapClient(System.ServiceModel.Channels.Binding binding, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(binding, remoteAddress)
        {
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        ServiceReferenceRemoteSignature.GetSigningCertificateResponse ServiceReferenceRemoteSignature.RemoteSignatureSoap.GetSigningCertificate(ServiceReferenceRemoteSignature.GetSigningCertificateRequest request)
        {
            return base.Channel.GetSigningCertificate(request);
        }
        
        public byte[] GetSigningCertificate()
        {
            ServiceReferenceRemoteSignature.GetSigningCertificateRequest inValue = new ServiceReferenceRemoteSignature.GetSigningCertificateRequest();
            inValue.Body = new ServiceReferenceRemoteSignature.GetSigningCertificateRequestBody();
            ServiceReferenceRemoteSignature.GetSigningCertificateResponse retVal = ((ServiceReferenceRemoteSignature.RemoteSignatureSoap)(this)).GetSigningCertificate(inValue);
            return retVal.Body.GetSigningCertificateResult;
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        System.Threading.Tasks.Task<ServiceReferenceRemoteSignature.GetSigningCertificateResponse> ServiceReferenceRemoteSignature.RemoteSignatureSoap.GetSigningCertificateAsync(ServiceReferenceRemoteSignature.GetSigningCertificateRequest request)
        {
            return base.Channel.GetSigningCertificateAsync(request);
        }
        
        public System.Threading.Tasks.Task<ServiceReferenceRemoteSignature.GetSigningCertificateResponse> GetSigningCertificateAsync()
        {
            ServiceReferenceRemoteSignature.GetSigningCertificateRequest inValue = new ServiceReferenceRemoteSignature.GetSigningCertificateRequest();
            inValue.Body = new ServiceReferenceRemoteSignature.GetSigningCertificateRequestBody();
            return ((ServiceReferenceRemoteSignature.RemoteSignatureSoap)(this)).GetSigningCertificateAsync(inValue);
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        ServiceReferenceRemoteSignature.RemoteSignResponse ServiceReferenceRemoteSignature.RemoteSignatureSoap.RemoteSign(ServiceReferenceRemoteSignature.RemoteSignRequest request)
        {
            return base.Channel.RemoteSign(request);
        }
        
        public byte[] RemoteSign(byte[] hashToSign, ServiceReferenceRemoteSignature.HashAlgorithm signatureAlgorithm)
        {
            ServiceReferenceRemoteSignature.RemoteSignRequest inValue = new ServiceReferenceRemoteSignature.RemoteSignRequest();
            inValue.Body = new ServiceReferenceRemoteSignature.RemoteSignRequestBody();
            inValue.Body.hashToSign = hashToSign;
            inValue.Body.signatureAlgorithm = signatureAlgorithm;
            ServiceReferenceRemoteSignature.RemoteSignResponse retVal = ((ServiceReferenceRemoteSignature.RemoteSignatureSoap)(this)).RemoteSign(inValue);
            return retVal.Body.RemoteSignResult;
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        System.Threading.Tasks.Task<ServiceReferenceRemoteSignature.RemoteSignResponse> ServiceReferenceRemoteSignature.RemoteSignatureSoap.RemoteSignAsync(ServiceReferenceRemoteSignature.RemoteSignRequest request)
        {
            return base.Channel.RemoteSignAsync(request);
        }
        
        public System.Threading.Tasks.Task<ServiceReferenceRemoteSignature.RemoteSignResponse> RemoteSignAsync(byte[] hashToSign, ServiceReferenceRemoteSignature.HashAlgorithm signatureAlgorithm)
        {
            ServiceReferenceRemoteSignature.RemoteSignRequest inValue = new ServiceReferenceRemoteSignature.RemoteSignRequest();
            inValue.Body = new ServiceReferenceRemoteSignature.RemoteSignRequestBody();
            inValue.Body.hashToSign = hashToSign;
            inValue.Body.signatureAlgorithm = signatureAlgorithm;
            return ((ServiceReferenceRemoteSignature.RemoteSignatureSoap)(this)).RemoteSignAsync(inValue);
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        ServiceReferenceRemoteSignature.RemoteSignWithOidResponse ServiceReferenceRemoteSignature.RemoteSignatureSoap.RemoteSignWithOid(ServiceReferenceRemoteSignature.RemoteSignWithOidRequest request)
        {
            return base.Channel.RemoteSignWithOid(request);
        }
        
        public byte[] RemoteSignWithOid(byte[] hashToSign, string signatureAlgorithmOID)
        {
            ServiceReferenceRemoteSignature.RemoteSignWithOidRequest inValue = new ServiceReferenceRemoteSignature.RemoteSignWithOidRequest();
            inValue.Body = new ServiceReferenceRemoteSignature.RemoteSignWithOidRequestBody();
            inValue.Body.hashToSign = hashToSign;
            inValue.Body.signatureAlgorithmOID = signatureAlgorithmOID;
            ServiceReferenceRemoteSignature.RemoteSignWithOidResponse retVal = ((ServiceReferenceRemoteSignature.RemoteSignatureSoap)(this)).RemoteSignWithOid(inValue);
            return retVal.Body.RemoteSignWithOidResult;
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        System.Threading.Tasks.Task<ServiceReferenceRemoteSignature.RemoteSignWithOidResponse> ServiceReferenceRemoteSignature.RemoteSignatureSoap.RemoteSignWithOidAsync(ServiceReferenceRemoteSignature.RemoteSignWithOidRequest request)
        {
            return base.Channel.RemoteSignWithOidAsync(request);
        }
        
        public System.Threading.Tasks.Task<ServiceReferenceRemoteSignature.RemoteSignWithOidResponse> RemoteSignWithOidAsync(byte[] hashToSign, string signatureAlgorithmOID)
        {
            ServiceReferenceRemoteSignature.RemoteSignWithOidRequest inValue = new ServiceReferenceRemoteSignature.RemoteSignWithOidRequest();
            inValue.Body = new ServiceReferenceRemoteSignature.RemoteSignWithOidRequestBody();
            inValue.Body.hashToSign = hashToSign;
            inValue.Body.signatureAlgorithmOID = signatureAlgorithmOID;
            return ((ServiceReferenceRemoteSignature.RemoteSignatureSoap)(this)).RemoteSignWithOidAsync(inValue);
        }
        
        public virtual System.Threading.Tasks.Task OpenAsync()
        {
            return System.Threading.Tasks.Task.Factory.FromAsync(((System.ServiceModel.ICommunicationObject)(this)).BeginOpen(null, null), new System.Action<System.IAsyncResult>(((System.ServiceModel.ICommunicationObject)(this)).EndOpen));
        }
        
        public virtual System.Threading.Tasks.Task CloseAsync()
        {
            return System.Threading.Tasks.Task.Factory.FromAsync(((System.ServiceModel.ICommunicationObject)(this)).BeginClose(null, null), new System.Action<System.IAsyncResult>(((System.ServiceModel.ICommunicationObject)(this)).EndClose));
        }
        
        private static System.ServiceModel.Channels.Binding GetBindingForEndpoint(EndpointConfiguration endpointConfiguration)
        {
            if ((endpointConfiguration == EndpointConfiguration.RemoteSignatureSoap))
            {
                System.ServiceModel.BasicHttpBinding result = new System.ServiceModel.BasicHttpBinding();
                result.MaxBufferSize = int.MaxValue;
                result.ReaderQuotas = System.Xml.XmlDictionaryReaderQuotas.Max;
                result.MaxReceivedMessageSize = int.MaxValue;
                result.AllowCookies = true;
                result.Security.Mode = System.ServiceModel.BasicHttpSecurityMode.Transport;
                return result;
            }
            if ((endpointConfiguration == EndpointConfiguration.RemoteSignatureSoap12))
            {
                System.ServiceModel.Channels.CustomBinding result = new System.ServiceModel.Channels.CustomBinding();
                System.ServiceModel.Channels.TextMessageEncodingBindingElement textBindingElement = new System.ServiceModel.Channels.TextMessageEncodingBindingElement();
                textBindingElement.MessageVersion = System.ServiceModel.Channels.MessageVersion.CreateVersion(System.ServiceModel.EnvelopeVersion.Soap12, System.ServiceModel.Channels.AddressingVersion.None);
                result.Elements.Add(textBindingElement);
                System.ServiceModel.Channels.HttpsTransportBindingElement httpsBindingElement = new System.ServiceModel.Channels.HttpsTransportBindingElement();
                httpsBindingElement.AllowCookies = true;
                httpsBindingElement.MaxBufferSize = int.MaxValue;
                httpsBindingElement.MaxReceivedMessageSize = int.MaxValue;
                result.Elements.Add(httpsBindingElement);
                return result;
            }
            throw new System.InvalidOperationException(string.Format("Could not find endpoint with name \'{0}\'.", endpointConfiguration));
        }
        
        private static System.ServiceModel.EndpointAddress GetEndpointAddress(EndpointConfiguration endpointConfiguration)
        {
            if ((endpointConfiguration == EndpointConfiguration.RemoteSignatureSoap))
            {
                return new System.ServiceModel.EndpointAddress("https://ca.t4trust.ae/RemoteSigner/RemoteSignature.asmx");
            }
            if ((endpointConfiguration == EndpointConfiguration.RemoteSignatureSoap12))
            {
                return new System.ServiceModel.EndpointAddress("https://ca.t4trust.ae/RemoteSigner/RemoteSignature.asmx");
            }
            throw new System.InvalidOperationException(string.Format("Could not find endpoint with name \'{0}\'.", endpointConfiguration));
        }
        
        public enum EndpointConfiguration
        {
            
            RemoteSignatureSoap,
            
            RemoteSignatureSoap12,
        }
    }
}