use dmc_model::{Catalog, SqlDataType};
use dmc_sql_front::{
    BinaryOp, Expr, FunctionArg, SourceSpan, UnaryOp,
};

use crate::bound::{BoundColumnRef, BoundExpr, BoundFunctionArg, BoundValue};
use crate::error::{BindError, Result};
use crate::scope::BindScope;
use crate::types::{
    arithmetic_result_type, bind_literal, bind_null_value, check_compatible, comparison_compatible,
    comparison_result_type, is_null_literal,
};

pub fn bind_expr(
    catalog: &Catalog,
    scope: &BindScope,
    expr: &Expr,
) -> Result<BoundExpr> {
    match expr {
        Expr::Literal { value, span } => {
            if matches!(value, dmc_sql_front::SqlValue::Null) {
                Ok(BoundExpr::Literal {
                    value: bind_null_value(),
                    span: *span,
                })
            } else {
                Ok(BoundExpr::Literal {
                    value: bind_literal(value.clone(), *span)?,
                    span: *span,
                })
            }
        }
        Expr::Identifier { name, span } => bind_column_ref(catalog, scope, None, &name.name, *span),
        Expr::Qualified { parts, span } => {
            if parts.len() == 2 {
                bind_column_ref(catalog, scope, Some(&parts[0].name), &parts[1].name, *span)
            } else {
                Err(BindError::UnknownColumn {
                    name: parts
                        .iter()
                        .map(|p| p.name.as_str())
                        .collect::<Vec<_>>()
                        .join("."),
                    span: *span,
                })
            }
        }
        Expr::Binary { left, op, right, span } => {
            if matches!(op, BinaryOp::Eq | BinaryOp::Ne)
                && (is_null_literal(left) || is_null_literal(right))
            {
                return Err(BindError::InvalidNullComparison { span: *span });
            }
            let left = bind_expr(catalog, scope, left)?;
            let right = bind_expr(catalog, scope, right)?;
            let data_type = bind_binary_type(*op, &left, &right, *span)?;
            Ok(BoundExpr::Binary {
                left: Box::new(left),
                op: *op,
                right: Box::new(right),
                data_type,
                span: *span,
            })
        }
        Expr::Unary { op, expr, span } => {
            let inner = bind_expr(catalog, scope, expr)?;
            let data_type = bind_unary_type(*op, &inner, *span)?;
            Ok(BoundExpr::Unary {
                op: *op,
                expr: Box::new(inner),
                data_type,
                span: *span,
            })
        }
        Expr::Function { name, args, span } => bind_function(catalog, scope, name, args, *span),
        Expr::IsNull { expr, negated, span } => {
            let inner = bind_expr(catalog, scope, expr)?;
            Ok(BoundExpr::IsNull {
                expr: Box::new(inner),
                negated: *negated,
                data_type: SqlDataType::Boolean,
                span: *span,
            })
        }
        Expr::In { expr, values, negated, span } => {
            let inner = bind_expr(catalog, scope, expr)?;
            let inner_ty = inner.data_type().clone();
            let mut bound_values = Vec::with_capacity(values.len());
            for value in values {
                let bound = bind_expr(catalog, scope, value)?;
                check_compatible(&inner_ty, bound.data_type(), bound.span())?;
                bound_values.push(bound);
            }
            Ok(BoundExpr::In {
                expr: Box::new(inner),
                values: bound_values,
                negated: *negated,
                data_type: SqlDataType::Boolean,
                span: *span,
            })
        }
    }
}

fn bind_column_ref(
    catalog: &Catalog,
    scope: &BindScope,
    qualifier: Option<&str>,
    name: &str,
    span: SourceSpan,
) -> Result<BoundExpr> {
    let (table_id, column_id, column) = scope.resolve_column(catalog, qualifier, name, span)?;
    Ok(BoundExpr::Column(BoundColumnRef {
        table_id,
        column_id,
        data_type: column.data_type.clone(),
        nullable: column.nullable,
        span,
    }))
}

fn bind_binary_type(
    op: BinaryOp,
    left: &BoundExpr,
    right: &BoundExpr,
    span: SourceSpan,
) -> Result<SqlDataType> {
    match op {
        BinaryOp::Or | BinaryOp::And => {
            check_compatible(&SqlDataType::Boolean, left.data_type(), left.span())?;
            check_compatible(&SqlDataType::Boolean, right.data_type(), right.span())?;
            Ok(comparison_result_type())
        }
        BinaryOp::Eq
        | BinaryOp::Ne
        | BinaryOp::Lt
        | BinaryOp::Le
        | BinaryOp::Gt
        | BinaryOp::Ge => {
            comparison_compatible(left.data_type(), right.data_type(), span)?;
            Ok(comparison_result_type())
        }
        BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => {
            arithmetic_result_type(left.data_type(), right.data_type(), span)
        }
    }
}

fn bind_unary_type(op: UnaryOp, expr: &BoundExpr, span: SourceSpan) -> Result<SqlDataType> {
    match op {
        UnaryOp::Not => {
            check_compatible(&SqlDataType::Boolean, expr.data_type(), expr.span())?;
            Ok(SqlDataType::Boolean)
        }
        UnaryOp::Neg => arithmetic_result_type(expr.data_type(), expr.data_type(), span),
    }
}

fn bind_function(
    catalog: &Catalog,
    scope: &BindScope,
    name: &dmc_sql_front::Ident,
    args: &[FunctionArg],
    span: SourceSpan,
) -> Result<BoundExpr> {
    let upper = name.name.to_ascii_uppercase();
    let mut bound_args = Vec::with_capacity(args.len());
    for arg in args {
        bound_args.push(match arg {
            FunctionArg::Star { .. } => BoundFunctionArg::Star,
            FunctionArg::Expr(expr) => {
                BoundFunctionArg::Expr(bind_expr(catalog, scope, expr)?)
            }
        });
    }
    let data_type = resolve_function_type(&upper, &bound_args, span)?;
    Ok(BoundExpr::Function {
        name: upper,
        args: bound_args,
        data_type,
        span,
    })
}

fn resolve_function_type(
    name: &str,
    args: &[BoundFunctionArg],
    span: SourceSpan,
) -> Result<SqlDataType> {
    match name {
        "COUNT" => {
            if args.len() != 1 {
                return Err(BindError::InvalidFunctionArguments {
                    name: name.into(),
                    message: "COUNT expects exactly one argument".into(),
                    span,
                });
            }
            Ok(SqlDataType::BigInt)
        }
        "SUM" => {
            if args.len() != 1 {
                return Err(BindError::InvalidFunctionArguments {
                    name: name.into(),
                    message: "SUM expects exactly one argument".into(),
                    span,
                });
            }
            let arg_ty = function_arg_type(&args[0])?;
            match arg_ty {
                SqlDataType::Integer => Ok(SqlDataType::BigInt),
                SqlDataType::BigInt => Ok(SqlDataType::BigInt),
                SqlDataType::Double => Ok(SqlDataType::Double),
                SqlDataType::Decimal { .. } => Ok(SqlDataType::Decimal {
                    precision: 38,
                    scale: 10,
                }),
                other => Err(BindError::InvalidFunctionArguments {
                    name: name.into(),
                    message: format!("SUM does not accept {other:?}"),
                    span,
                }),
            }
        }
        "AVG" => {
            if args.len() != 1 {
                return Err(BindError::InvalidFunctionArguments {
                    name: name.into(),
                    message: "AVG expects exactly one argument".into(),
                    span,
                });
            }
            let arg_ty = function_arg_type(&args[0])?;
            if matches!(
                arg_ty,
                SqlDataType::Integer
                    | SqlDataType::BigInt
                    | SqlDataType::Double
                    | SqlDataType::Decimal { .. }
            ) {
                Ok(SqlDataType::Double)
            } else {
                Err(BindError::InvalidFunctionArguments {
                    name: name.into(),
                    message: format!("AVG does not accept {arg_ty:?}"),
                    span,
                })
            }
        }
        other => Err(BindError::UnknownFunction {
            name: other.into(),
            span,
        }),
    }
}

fn function_arg_type(arg: &BoundFunctionArg) -> Result<SqlDataType> {
    match arg {
        BoundFunctionArg::Star => Ok(SqlDataType::BigInt),
        BoundFunctionArg::Expr(expr) => Ok(expr.data_type().clone()),
    }
}

pub fn bind_sql_value(
    value: &dmc_sql_front::SqlValue,
    span: SourceSpan,
) -> Result<BoundValue> {
    if matches!(value, dmc_sql_front::SqlValue::Null) {
        Ok(bind_null_value())
    } else {
        bind_literal(value.clone(), span)
    }
}
