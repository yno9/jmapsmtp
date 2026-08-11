//! The live DNS client, and the trait the rest of the relay talks to.
//!
//! Two lookups matter here, and both decide something consequential:
//!
//! - **MX**, for where a message goes. A wrong answer delivers mail to the
//!   wrong host.
//! - **TXT**, for whether someone controls a domain. A wrong answer hands them
//!   a domain they do not own.
//!
//! Both sit behind traits so every decision above them is testable without a
//! network, and so the resolver is constructed once rather than per request.
//! This module holds the only live implementation.

use std::sync::Arc;

use crate::smtp_out::MxResolver;

/// Resolves the TXT records used to prove control of a domain.
pub trait TxtResolver: Send + Sync {
    /// Every TXT record at `name`. Empty on any failure — a lookup that did
    /// not answer is not proof of anything, and treating an error as "no
    /// records" is the same refusal as an empty answer.
    fn lookup_txt(&self, name: &str) -> Vec<String>;
}

/// The real resolver, reading the system configuration.
pub struct SystemDns {
    resolver: hickory_resolver::Resolver<hickory_resolver::name_server::TokioConnectionProvider>,
    /// Lookups happen from synchronous decision code, so each one is driven on
    /// this handle rather than by blocking the caller's runtime.
    handle: tokio::runtime::Handle,
}

impl SystemDns {
    /// Build a resolver from `/etc/resolv.conf`, falling back to the built-in
    /// defaults when it cannot be read.
    ///
    /// Must be called from inside a Tokio runtime.
    pub fn new() -> Arc<SystemDns> {
        let builder = hickory_resolver::Resolver::builder_tokio().unwrap_or_else(|_| {
            hickory_resolver::Resolver::builder_with_config(
                hickory_resolver::config::ResolverConfig::default(),
                hickory_resolver::name_server::TokioConnectionProvider::default(),
            )
        });
        Arc::new(SystemDns {
            resolver: builder.build(),
            handle: tokio::runtime::Handle::current(),
        })
    }

    fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        // `block_in_place` needs the multi-threaded runtime; without it a
        // current-thread runtime would deadlock on itself.
        tokio::task::block_in_place(|| self.handle.block_on(fut))
    }
}

impl MxResolver for SystemDns {
    fn lookup_mx(&self, domain: &str) -> Vec<String> {
        let Ok(response) = self.block_on(self.resolver.mx_lookup(domain)) else {
            return Vec::new();
        };
        let mut records: Vec<(u16, String)> = response
            .iter()
            .map(|mx| (mx.preference(), mx.exchange().to_string()))
            .collect();
        // Lowest preference first. Ties keep the order the server sent, which
        // is where a server does its own load spreading.
        records.sort_by_key(|(preference, _)| *preference);
        records
            .into_iter()
            .map(|(_, host)| host.trim_end_matches('.').to_string())
            .collect()
    }
}

impl TxtResolver for SystemDns {
    fn lookup_txt(&self, name: &str) -> Vec<String> {
        let Ok(response) = self.block_on(self.resolver.txt_lookup(name)) else {
            return Vec::new();
        };
        response
            .iter()
            .map(|txt| {
                // A TXT record is a sequence of strings, and a value longer
                // than 255 bytes arrives split. They are concatenated with no
                // separator, which is what every TXT consumer does and what
                // Go's net.LookupTXT returns.
                txt.iter()
                    .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                    .collect::<String>()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
