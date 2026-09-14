use std::collections::BTreeSet;

use dmc_model::{ColumnId, SqlDataType, TableId};
use dmc_sql_bind::{BoundExpr, BoundFunctionArg, BoundValue};
use dmc_sql_front::{BinaryOp, SourceSpan, SqlValue, UnaryOp};

pub fn split_conjunction(expr: &BoundExpr) -> Vec<BoundExpr> {
    match expr {
        BoundExpr::Binary { op: BinaryOp::And, left, right, .. } => {
            let mut parts = split_conjunction(left);
            parts.extend(split_conjunction(right));
            parts
        }
        other => vec![other.clone()],
    }
}

pub fn combine_conjunction(predicates: Vec<BoundExpr>) -> Option<BoundExpr> {
    let mut iter = predicates.into_iter();
    let first = iter.next()?;
    Some(iter.fold(first, |acc, next| {
        let span = acc.span().merge(next.span());
        BoundExpr::Binary {
            left: Box::new(acc),
            op: BinaryOp::And,
            right: Box::new(next),
            data_type: SqlDataType::Boolean,
            span,
        }
    }))
}

pub fn tables_in_expr(expr: &BoundExpr) -> BTreeSet<TableId> {
    let mut out = BTreeSet::new();
    collect_tables_expr(expr, &mut out);
    out
}

pub fn columns_in_expr(expr: &BoundExpr) -> BTreeSet<(TableId, ColumnId)> {
    let mut out = BTreeSet::new();
    collect_columns_expr(expr, &mut out);
    out
}

fn collect_tables_expr(expr: &BoundExpr, out: &mut BTreeSet<TableId>) {
    match expr {
        BoundExpr::Column(col) => {
            out.insert(col.table_id);
        }
        BoundExpr::Binary { left, right, .. } => {
            collect_tables_expr(left, out);
            collect_tables_expr(right, out);
        }
        BoundExpr::Unary { expr, .. } => collect_tables_expr(expr, out),
        BoundExpr::Function { args, .. } => {
            for arg in args {
                if let BoundFunctionArg::Expr(e) = arg {
                    collect_tables_expr(e, out);
                }
            }
        }
        BoundExpr::IsNull { expr, .. } => collect_tables_expr(expr, out),
        BoundExpr::In { expr, values, .. } => {
            collect_tables_expr(expr, out);
            for v in values {
                collect_tables_expr(v, out);
            }
        }
        BoundExpr::Literal { .. } => {}
    }
}

fn collect_columns_expr(expr: &BoundExpr, out: &mut BTreeSet<(TableId, ColumnId)>) {
    match expr {
        BoundExpr::Column(col) => {
            out.insert((col.table_id, col.column_id));
        }
        BoundExpr::Binary { left, right, .. } => {
            collect_columns_expr(left, out);
            collect_columns_expr(right, out);
        }
        BoundExpr::Unary { expr, .. } => collect_columns_expr(expr, out),
        BoundExpr::Function { args, .. } => {
            for arg in args {
                if let BoundFunctionArg::Expr(e) = arg {
                    collect_columns_expr(e, out);
                }
            }
        }
        BoundExpr::IsNull { expr, .. } => collect_columns_expr(expr, out),
        BoundExpr::In { expr, values, .. } => {
            collect_columns_expr(expr, out);
            for v in values {
                collect_columns_expr(v, out);
            }
        }
        BoundExpr::Literal { .. } => {}
    }
}

pub fn map_expr(expr: &BoundExpr, f: &mut dyn FnMut(BoundExpr) -> BoundExpr) -> BoundExpr {
    let mapped = match expr {
        BoundExpr::Binary { left, op, right, data_type, span } => BoundExpr::Binary {
            left: Box::new(map_expr(left, f)),
            op: *op,
            right: Box::new(map_expr(right, f)),
            data_type: data_type.clone(),
            span: *span,
        },
        BoundExpr::Unary { op, expr, data_type, span } => BoundExpr::Unary {
            op: *op,
            expr: Box::new(map_expr(expr, f)),
            data_type: data_type.clone(),
            span: *span,
        },
        BoundExpr::Function { name, args, data_type, span } => BoundExpr::Function {
            name: name.clone(),
            args: args
                .iter()
                .map(|arg| match arg {
                    BoundFunctionArg::Star => BoundFunctionArg::Star,
                    BoundFunctionArg::Expr(e) => BoundFunctionArg::Expr(map_expr(e, f)),
                })
                .collect(),
            data_type: data_type.clone(),
            span: *span,
        },
        BoundExpr::IsNull { expr, negated, data_type, span } => BoundExpr::IsNull {
            expr: Box::new(map_expr(expr, f)),
            negated: *negated,
            data_type: data_type.clone(),
            span: *span,
        },
        BoundExpr::In { expr, values, negated, data_type, span } => BoundExpr::In {
            expr: Box::new(map_expr(expr, f)),
            values: values.iter().map(|v| map_expr(v, f)).collect(),
            negated: *negated,
            data_type: data_type.clone(),
            span: *span,
        },
        other => other.clone(),
    };
    f(mapped)
}

pub fn bool_literal(value: bool, span: SourceSpan) -> BoundExpr {
    BoundExpr::Literal {
        value: BoundValue {
            value: SqlValue::Boolean(value),
            data_type: SqlDataType::Boolean,
        },
        span,
    }
}

pub fn is_bool_literal(expr: &BoundExpr, value: bool) -> bool {
    matches!(
        expr,
        BoundExpr::Literal {
            value: BoundValue {
                value: SqlValue::Boolean(v),
                ..
            },
            ..
        } if *v == value
    )
}

pub fn is_true_literal(expr: &BoundExpr) -> bool {
    is_bool_literal(expr, true)
}

pub fn is_false_literal(expr: &BoundExpr) -> bool {
    is_bool_literal(expr, false)
}

pub fn fold_binary(op: BinaryOp, left: &BoundExpr, right: &BoundExpr, span: SourceSpan) -> Option<BoundExpr> {
    match op {
        BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => {
            fold_numeric_binary(op, left, right, span)
        }
        BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
            fold_comparison(op, left, right, span)
        }
        BinaryOp::And | BinaryOp::Or => None,
    }
}

fn fold_numeric_binary(op: BinaryOp, left: &BoundExpr, right: &BoundExpr, span: SourceSpan) -> Option<BoundExpr> {
    let (lv, ty) = literal_i64(left)?;
    let rv = literal_i64(right)?.0;
    let result = match op {
        BinaryOp::Add => lv + rv,
        BinaryOp::Sub => lv - rv,
        BinaryOp::Mul => lv * rv,
        BinaryOp::Div if rv != 0 => lv / rv,
        BinaryOp::Mod if rv != 0 => lv % rv,
        _ => return None,
    };
    Some(BoundExpr::Literal {
        value: BoundValue {
            value: SqlValue::Integer(result),
            data_type: ty,
        },
        span,
    })
}

fn fold_comparison(op: BinaryOp, left: &BoundExpr, right: &BoundExpr, span: SourceSpan) -> Option<BoundExpr> {
    let (lv, _) = literal_i64(left)?;
    let rv = literal_i64(right)?.0;
    let result = match op {
        BinaryOp::Eq => lv == rv,
        BinaryOp::Ne => lv != rv,
        BinaryOp::Lt => lv < rv,
        BinaryOp::Le => lv <= rv,
        BinaryOp::Gt => lv > rv,
        BinaryOp::Ge => lv >= rv,
        _ => return None,
    };
    Some(bool_literal(result, span))
}

fn literal_i64(expr: &BoundExpr) -> Option<(i64, SqlDataType)> {
    match expr {
        BoundExpr::Literal {
            value: BoundValue {
                value: SqlValue::Integer(v),
                data_type,
            },
            ..
        } => Some((*v, data_type.clone())),
        _ => None,
    }
}

pub fn simplify_boolean(expr: BoundExpr) -> BoundExpr {
    match expr {
        BoundExpr::Unary {
            op: UnaryOp::Not,
            expr,
            data_type,
            span,
        } => {
            let inner = simplify_boolean(*expr);
            if let BoundExpr::Unary {
                op: UnaryOp::Not,
                expr: inner2,
                ..
            } = inner
            {
                return *inner2;
            }
            BoundExpr::Unary {
                op: UnaryOp::Not,
                expr: Box::new(inner),
                data_type,
                span,
            }
        }
        BoundExpr::Binary {
            op: BinaryOp::And,
            left,
            right,
            data_type,
            span,
        } => {
            let left = simplify_boolean(*left);
            let right = simplify_boolean(*right);
            if is_true_literal(&left) {
                return right;
            }
            if is_false_literal(&left) || is_false_literal(&right) {
                return bool_literal(false, span);
            }
            if is_true_literal(&right) {
                return left;
            }
            BoundExpr::Binary {
                op: BinaryOp::And,
                left: Box::new(left),
                right: Box::new(right),
                data_type,
                span,
            }
        }
        BoundExpr::Binary {
            op: BinaryOp::Or,
            left,
            right,
            data_type,
            span,
        } => {
            let left = simplify_boolean(*left);
            let right = simplify_boolean(*right);
            if is_false_literal(&left) {
                return right;
            }
            if is_true_literal(&left) || is_true_literal(&right) {
                return bool_literal(true, span);
            }
            if is_false_literal(&right) {
                return left;
            }
            BoundExpr::Binary {
                op: BinaryOp::Or,
                left: Box::new(left),
                right: Box::new(right),
                data_type,
                span,
            }
        }
        other => other,
    }
}

pub fn fold_constants(expr: BoundExpr) -> BoundExpr {
    match expr {
        BoundExpr::Binary {
            op,
            left,
            right,
            data_type,
            span,
        } => {
            let left = fold_constants(*left);
            let right = fold_constants(*right);
            if let Some(folded) = fold_binary(op, &left, &right, span) {
                return folded;
            }
            BoundExpr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
                data_type,
                span,
            }
        }
        BoundExpr::Unary { op, expr, data_type, span } => BoundExpr::Unary {
            op,
            expr: Box::new(fold_constants(*expr)),
            data_type,
            span,
        },
        BoundExpr::Function { name, args, data_type, span } => BoundExpr::Function {
            name,
            args: args
                .into_iter()
                .map(|arg| match arg {
                    BoundFunctionArg::Star => BoundFunctionArg::Star,
                    BoundFunctionArg::Expr(e) => BoundFunctionArg::Expr(fold_constants(e)),
                })
                .collect(),
            data_type,
            span,
        },
        BoundExpr::IsNull { expr, negated, data_type, span } => BoundExpr::IsNull {
            expr: Box::new(fold_constants(*expr)),
            negated,
            data_type,
            span,
        },
        BoundExpr::In { expr, values, negated, data_type, span } => BoundExpr::In {
            expr: Box::new(fold_constants(*expr)),
            values: values.into_iter().map(fold_constants).collect(),
            negated,
            data_type,
            span,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use dmc_model::SqlDataType;
    use dmc_sql_bind::BoundValue;
    use dmc_sql_front::{BinaryOp, SourceSpan, SqlValue, UnaryOp};

    use super::*;

    fn int_lit(v: i64) -> BoundExpr {
        BoundExpr::Literal {
            value: BoundValue {
                value: SqlValue::Integer(v),
                data_type: SqlDataType::Integer,
            },
            span: SourceSpan::default(),
        }
    }

    #[test]
    fn folds_integer_addition() {
        let expr = BoundExpr::Binary {
            left: Box::new(int_lit(1)),
            op: BinaryOp::Add,
            right: Box::new(int_lit(2)),
            data_type: SqlDataType::Integer,
            span: SourceSpan::default(),
        };
        let folded = fold_constants(expr);
        assert!(matches!(
            folded,
            BoundExpr::Literal {
                value: BoundValue {
                    value: SqlValue::Integer(3),
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn simplifies_true_and_x() {
        let x = int_lit(1);
        let expr = BoundExpr::Binary {
            left: Box::new(bool_literal(true, SourceSpan::default())),
            op: BinaryOp::And,
            right: Box::new(x.clone()),
            data_type: SqlDataType::Boolean,
            span: SourceSpan::default(),
        };
        assert_eq!(simplify_boolean(expr), x);
    }

    #[test]
    fn simplifies_double_not() {
        let x = int_lit(5);
        let expr = BoundExpr::Unary {
            op: UnaryOp::Not,
            expr: Box::new(BoundExpr::Unary {
                op: UnaryOp::Not,
                expr: Box::new(x.clone()),
                data_type: SqlDataType::Integer,
                span: SourceSpan::default(),
            }),
            data_type: SqlDataType::Boolean,
            span: SourceSpan::default(),
        };
        assert_eq!(simplify_boolean(expr), x);
    }

    #[test]
    fn splits_conjunction_at_and() {
        let expr = BoundExpr::Binary {
            left: Box::new(int_lit(1)),
            op: BinaryOp::And,
            right: Box::new(int_lit(2)),
            data_type: SqlDataType::Boolean,
            span: SourceSpan::default(),
        };
        assert_eq!(split_conjunction(&expr).len(), 2);
    }
}
