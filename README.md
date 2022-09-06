# Cards Transactions Examples

This repository contains Public code examples to help the integration with the card transactions product.

Before you proceed, we recommend reading the public documentation at [https://developers.pomelo.la/en/api-reference/cards/transactions](https://developers.pomelo.la/en/api-reference/cards/transactions)

If you want to learn more about the Pomelo Cards product, please visit [https://www.pomelo.la/en/credit-debit-cards-prepaid/](https://www.pomelo.la/en/credit-debit-cards-prepaid/)

## Repository Contents

In this repository you'll find example code to handle card transaction authorizations and adjustments.

Remember that during the authorization process, Pomelo will send a webhook to your backend requesting whether you
APPROVE or REJECT the transaction. This repository helps you build and test tha backend using our pre-made examples
and other helper files.

* `Client.postman_collection.json`

    We include a sample [Postman](https://www.postman.com/) collection (`Client.postman_collection.json`) so you can test your backend implementation.
    This collection contains several use cases that we will test during the homologation process, so make sure you review all of them!
    If you are unsure how to import the collection, please browse the [Postman documentation](https://learning.postman.com/docs/getting-started/introduction/).

* `signature`

    This directory contains example code in several languages on how to handle the [request signature process](https://developers.pomelo.la/en/api-reference/cards/transactions#cards-transactions-request-signature-process)
    that you'll need to implement to validate requests are being sent by Pomelo and not an attacker. The code also shows how
    to sign responses, which we also require.

## Contributing

We are not accepting pull requests at the moment. If you find a major bug or a security threat, please open a github issue. Note that we **do not offer support** through github issues.

If you need sales or technical support, please contact us through [our website](https://www.pomelo.la/en/contact-us/).

## License
[MIT](https://choosealicense.com/licenses/mit/)