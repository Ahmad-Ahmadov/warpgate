use super::target::{
    Target, TargetHTTPOptions, TargetKubernetesOptions, TargetMySqlOptions, TargetOptions,
    TargetPostgresOptions, TargetRdpOptions, TargetSSHOptions, TargetVncOptions,
};
use crate::{Protocol, WarpgateError};

/// Inner value of a [`TargetOptions`] variant
pub trait TargetOptionsVariant: Clone {
    const PROTOCOL: Protocol;
    fn extract(options: &TargetOptions) -> Option<&Self>;
}

macro_rules! target_options_variant {
    ($variant:ident, $options:ty, $protocol:expr) => {
        impl TargetOptionsVariant for $options {
            const PROTOCOL: Protocol = $protocol;
            fn extract(options: &TargetOptions) -> Option<&Self> {
                match options {
                    TargetOptions::$variant(options) => Some(options),
                    _ => None,
                }
            }
        }
    };
}

target_options_variant!(Ssh, TargetSSHOptions, Protocol::Ssh);
target_options_variant!(Http, TargetHTTPOptions, Protocol::Http);
target_options_variant!(Kubernetes, TargetKubernetesOptions, Protocol::Kubernetes);
target_options_variant!(MySql, TargetMySqlOptions, Protocol::MySql);
target_options_variant!(Postgres, TargetPostgresOptions, Protocol::Postgres);
target_options_variant!(Vnc, TargetVncOptions, Protocol::Vnc);
target_options_variant!(Rdp, TargetRdpOptions, Protocol::Rdp);

/// A [`Target`], optionally narrowed down to a specific protocol/type
#[derive(Debug, Clone)]
pub struct SpecificTarget<O = TargetOptions> {
    target: Target,
    /// A copy of the matching variant, so `options()` is direct field access.
    options: O,
}

impl<O> SpecificTarget<O> {
    pub const fn options(&self) -> &O {
        &self.options
    }

    pub fn into_parts(self) -> (Target, O) {
        (self.target, self.options)
    }
}

impl<O: TargetOptionsVariant> SpecificTarget<O> {
    /// Narrows a freshly resolved target, fails when it is of another kind.
    pub fn new(target: Target) -> Result<Self, WarpgateError> {
        SpecificTarget::any(target).narrow()
    }

    pub const fn protocol(&self) -> Protocol {
        O::PROTOCOL
    }

    /// The same target with `change` applied to its options (both the full target's and the
    /// narrowed copy). For filling in the account a connection was authorized to sign in as;
    /// the capabilities that hold a `SpecificTarget` only offer it to the code that authorizes.
    pub fn with_options(
        mut self,
        change: impl FnOnce(&mut TargetOptions),
    ) -> Result<Self, WarpgateError> {
        change(&mut self.target.options);
        self.options = O::extract(&self.target.options)
            .ok_or(WarpgateError::InvalidTarget)?
            .clone();
        Ok(self)
    }
}

impl SpecificTarget<TargetOptions> {
    pub fn any(target: Target) -> Self {
        let options = target.options.clone();
        Self { target, options }
    }

    /// [`SpecificTarget::with_options`] for a target not narrowed to a protocol.
    #[must_use]
    pub fn with_any_options(mut self, change: impl FnOnce(&mut TargetOptions)) -> Self {
        change(&mut self.target.options);
        self.options = self.target.options.clone();
        self
    }

    pub fn narrow<O: TargetOptionsVariant>(self) -> Result<SpecificTarget<O>, WarpgateError> {
        match O::extract(&self.options) {
            Some(options) => {
                let options = options.clone();
                Ok(SpecificTarget {
                    target: self.target,
                    options,
                })
            }
            None => Err(WarpgateError::InvalidTarget),
        }
    }
}

impl<O> std::ops::Deref for SpecificTarget<O> {
    type Target = Target;
    fn deref(&self) -> &Target {
        &self.target
    }
}
