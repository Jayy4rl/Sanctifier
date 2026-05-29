//! Reentrancy analysis for Soroban contracts.
use quote::quote;
use serde::Serialize;
use syn::visit::Visit;
use syn::{File, ExprMethodCall, ExprCall};

/// Edge representing a cross-contract call.
#[derive(Debug, Serialize, Clone)]
pub struct ReentrancyEdge {
    pub caller_function: String,
    pub target_contract: String,
    pub target_function: String,
    pub function_expr: Option<String>,
}

pub fn scan_invoke_contract_calls(source: &str) -> Vec<ReentrancyEdge> {
    let file = match syn::parse_str::<File>(source) {
        Ok(f) => f,
        Err(_) => return vec![],
    };

    let mut visitor = CallVisitor { edges: Vec::new(), current_fn: String::new() };
    visitor.visit_file(&file);
    visitor.edges
}

struct CallVisitor {
    edges: Vec<ReentrancyEdge>,
    current_fn: String,
}

impl<'ast> Visit<'ast> for CallVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.current_fn = node.sig.ident.to_string();
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.current_fn = node.sig.ident.to_string();
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if node.method == "invoke_contract" || node.method == "call" {
             self.edges.push(ReentrancyEdge {
                 caller_function: self.current_fn.clone(),
                 target_contract: "Unknown".to_string(), // Placeholder
                 target_function: "Unknown".to_string(), // Placeholder
                 function_expr: Some(quote!(#node).to_string()),
             });
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        // Handle direct calls if needed
        syn::visit::visit_expr_call(self, node);
    }
}
