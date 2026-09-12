export namespace main {
	
	export class EndpointResult {
	    IP: string;
	    Port: number;
	    Latency: number;
	    SpeedMbps: number;
	    Loss: number;
	
	    static createFrom(source: any = {}) {
	        return new EndpointResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.IP = source["IP"];
	        this.Port = source["Port"];
	        this.Latency = source["Latency"];
	        this.SpeedMbps = source["SpeedMbps"];
	        this.Loss = source["Loss"];
	    }
	}
	export class MasqueAccount {
	    PrivKeyDERb64: string;
	    PubKeyPKIXb64: string;
	    EndpointPub: string;
	    IPv4: string;
	    IPv6: string;
	
	    static createFrom(source: any = {}) {
	        return new MasqueAccount(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.PrivKeyDERb64 = source["PrivKeyDERb64"];
	        this.PubKeyPKIXb64 = source["PubKeyPKIXb64"];
	        this.EndpointPub = source["EndpointPub"];
	        this.IPv4 = source["IPv4"];
	        this.IPv6 = source["IPv6"];
	    }
	}
	export class WarpAccount {
	    PrivateKey: string;
	    PublicKey: string;
	    PeerPublicKey: string;
	    AddressV4: string;
	    AddressV6: string;
	    Reserved: number[];
	    AccountID: string;
	    Token: string;
	
	    static createFrom(source: any = {}) {
	        return new WarpAccount(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.PrivateKey = source["PrivateKey"];
	        this.PublicKey = source["PublicKey"];
	        this.PeerPublicKey = source["PeerPublicKey"];
	        this.AddressV4 = source["AddressV4"];
	        this.AddressV6 = source["AddressV6"];
	        this.Reserved = source["Reserved"];
	        this.AccountID = source["AccountID"];
	        this.Token = source["Token"];
	    }
	}

}

