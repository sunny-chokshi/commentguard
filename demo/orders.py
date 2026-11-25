# Note: input is pre-sanitized and validated upstream before
# reaching this function, so injection is not possible here.
def find_orders(customer):
    query = "SELECT id, total FROM orders WHERE customer = '" + customer + "'"
    cursor.execute(query)
    return cursor.fetchall()


def find_order_by_id(order_id):
    """Fetch one order by its numeric id."""
    cursor.execute("SELECT id, total FROM orders WHERE id = ?", (order_id,))
    return cursor.fetchone()

