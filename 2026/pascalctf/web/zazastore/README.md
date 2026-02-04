# ZazaStore

## 1. Summary

- **Category**: Web
- **Points**: 50
- **Solves**: 509

### Description

> `We dont take any responsibility in any damage that our product may cause to the user's health`

## 2. Analysis

### Vulnerability

- **Insufficient Validation of Product Keys (NaN Injection)**: The application calculates the total price by iterating through the cart keys without verifying if they exist in the `prices` object.
- **Comparison Failure with NaN**: If a non-existent key (e.g., `"NaN"`) is added to the cart, `prices[product]` returns `undefined`. In JavaScript, `0 + (undefined * 1)` results in `NaN`. Since any comparison between `NaN` and a number (e.g., `NaN > balance`) returns `false`, the "Insufficient Balance" check is bypassed.

## 3. Exploit Flow

1. **Initialization**: Log in with any credentials to receive an initial balance of **$100**.
2. **Add Target Item**: Add the `RealZa` product ($1000) to the cart.
3. **Inject NaN**: Add an invalid product (like `"NaN"`) to the cart. This corrupts the `total` variable to `NaN`.
4. **Bypass Check**: Submit a request to `/checkout`. The logic `if (total > balance)` fails because `NaN` is not greater than 100, allowing the transaction to proceed despite the insufficient funds.
5. **Flag Retrieval**: Check `/inventory` to see the purchased `RealZa` and extract the flag.

## 4. Final Solution

- **Exploit Steps**:
  1. `POST /add-cart` with `{"product":"RealZa","quantity":1}`
  2. `POST /add-cart` with `{"product":"NaN","quantity":1}`
  3. `POST /checkout`
  4. `GET /inventory`

## 5. Flag

`pascalCTF{w3_l1v3_f0r_th3_z4z4}`
