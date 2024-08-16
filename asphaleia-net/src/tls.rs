use rustls::{
    pki_types::CertificateDer, server::ResolvesServerCertUsingSni, sign, ClientConfig,
    ClientConnection, DistinguishedName, Error, RootCertStore, ServerConfig, ServerConnection,
};
use std::ops::Deref;
use std::sync::Arc;

#[derive(Debug)]
pub struct TLSCertResolver {
    certs: ResolvesServerCertUsingSni,
}

impl TLSCertResolver {
    pub fn new() -> Self {
        Self {
            certs: ResolvesServerCertUsingSni::new(),
        }
    }

    pub fn from_ref(resolves_server_cert_using_sni: ResolvesServerCertUsingSni) -> Self {
        Self {
            certs: resolves_server_cert_using_sni,
        }
    }

    pub fn add(&mut self, name: &str, ck: sign::CertifiedKey) -> Result<(), Error> {
        self.certs.add(name, ck)
    }
}

impl rustls::server::ResolvesServerCert for TLSCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<sign::CertifiedKey>> {
        self.certs.resolve(client_hello)
    }
}

impl Deref for TLSCertResolver {
    type Target = ResolvesServerCertUsingSni;
    fn deref(&self) -> &Self::Target {
        &self.certs
    }
}

#[derive(Debug)]
pub struct TLSCertStore {
    store: RootCertStore,
}

impl TLSCertStore {
    pub fn new() -> Self {
        Self {
            store: RootCertStore::empty(),
        }
    }

    pub fn from_ref(root_cert_store: RootCertStore) -> Self {
        Self {
            store: root_cert_store,
        }
    }

    pub fn from_iter<'a, I>(iter: I) -> Self
    where
        I: IntoIterator<Item = CertificateDer<'a>>,
    {
        let mut store = RootCertStore::empty();
        store.add_parsable_certificates(iter);
        Self { store }
    }

    pub fn add(&mut self, der: CertificateDer<'_>) -> Result<(), rustls::Error> {
        self.store.add(der)
    }

    pub fn add_parsable_certificates<'a>(
        &mut self,
        der_certs: impl IntoIterator<Item = CertificateDer<'a>>,
    ) -> (usize, usize) {
        self.store.add_parsable_certificates(der_certs)
    }

    pub fn subjects(&self) -> Vec<DistinguishedName> {
        self.store.subjects()
    }

    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }
}

impl Deref for TLSCertStore {
    type Target = RootCertStore;
    fn deref(&self) -> &Self::Target {
        &self.store
    }
}

#[derive(Debug)]
pub struct TLSConnections {
    client_connection: ClientConnection,
    server_connection: ServerConnection,
}

impl TLSConnections {
    pub fn new(config: &TLSConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let client_connection = ClientConnection::new(
            config.client_config.clone(),
            rustls::pki_types::ServerName::try_from("localhost")?,
        )?;

        let server_connection = ServerConnection::new(config.server_config.clone())?;

        Ok(Self {
            client_connection,
            server_connection,
        })
    }

    pub fn client_connection(&self) -> &ClientConnection {
        &self.client_connection
    }

    pub fn server_connection(&self) -> &ServerConnection {
        &self.server_connection
    }
}

#[derive(Clone, Debug)]
pub struct TLSConfig {
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
}

impl TLSConfig {
    pub fn new(
        root_cert_store: TLSCertStore,
        resolver_cert_store: TLSCertResolver,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_cert_store.deref().clone())
                .with_no_client_auth(),
        );

        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(resolver_cert_store)),
        );

        Ok(Self {
            client_config,
            server_config,
        })
    }

    pub fn client_config(&self) -> &Arc<ClientConfig> {
        &self.client_config
    }

    pub fn server_config(&self) -> &Arc<ServerConfig> {
        &self.server_config
    }

    pub fn with_custom_cert_resolver<R>(self, resolver: R) -> Self
    where
        R: rustls::server::ResolvesServerCert + Send + Sync + 'static,
    {
        Self {
            client_config: self.client_config,
            server_config: Arc::new(
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(resolver)),
            ),
        }
    }
}

pub fn trusted_root_cert_store() -> TLSCertStore {
    TLSCertStore::from_ref(RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    ))
}
