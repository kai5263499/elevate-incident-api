# Elevate Incident API

## Running instructions

### Pre-requisites
The following assume rust-nightly is installed. If you need help installing and configuring rust take a look [here](https://www.rust-lang.org/tools/install)

### Incident API

Run all binary and library tests

```bash
cargo test
```

Build the api server binary 

```bash
cargo build --bin incident_api_server
```

Run the api server binary. Note: This requires elevate API credentials to exist in the environment variables `HTTP_USERNAME` and `HTTP_PASSWORD`

```
./incident_api_server
```

### Helper commands

Download the json response from identities and incident endpoints into the data directory

```bash
cargo run --bin incident_retriever
```

Process json files in the data directory instead of constantly hitting the live REST API endpoints

```bash
cargo run --bin incident_json_processor 
```

## Overall approach

### Language and project structure

I decide to use 
* Rust language for it's type safety and native multithreadding 
* [actix-web](https://crates.io/crates/actix-web) crate for the webserver logic. Note: I had to use the 4.0.0 beta version of this library in order to prevent a conflict with the [tokio](https://crates.io/crates/tokio) crate which I also used directly for a time
* [reqwest](https://crates.io/crates/reqwest) crate for making asynchronous HTTP requests
* [ordered-float](https://crates.io/crates/ordered-float) and [itertools](https://crates.io/crates/itertools) crates for ordering incidents by timestamp
* [serde_json](https://crates.io/crates/serde_json) crate for json operations

I also used a library project structure to encourage the isolation of shared structures and logic into a common library. Additionally, I included multiple binaries because I love writing one-off utilities to test different aspects of the overall system as I'm working on it.

### Incident API responses

I initially decided to map each incident api json response to a Rust struct type. Then I decided they were similar enough that I could collapse that into a more generic ApiResponse type. Then I discovered that some of the properties contained different value types, even in the same response body from a single endpoint! So I finally decided to use a generic `Map<String, Value>` and treat the json responses as generic blobs while preserving and keying off of the endpoint type as a string.

### Identities response

For the identities I created a structure that included two `HashMaps` mapping ip to employee_id and vice versa. I did this to make resolving ips to employee_id an O(1) operation.

### Aggregation

For the aggregation I decided to use a regular HashMap of incidents keyed by their timestamps as a 64-bit float. I then iterated through the sorted keys to build up the response which I modeled as a generic `HashMap`.

## Enhancements

Where to begin? 

### Lean more into language

I wrote this solution in Rust to help me gain profencincy in the language so many enhancements can broadly be lumped under the umbrella of gaining greater proficency with Rust. More specifically, I can tell the code I produced is not very Rust-like compared to other libraries.

There are two broad areas of improvement under this point. The first one is eliminating mutating code (identified by the `mut` keyword) in favor of more functional immutable functors. The second one is to elimnate my prolific use of `unwrap()` statements to avoid dealing with negative cases where errors can be returned from underlying methods.

### Lean more into the actix framework

I didn't realize until late into developing my solution that the actix framework provides an [Actor system](https://actix.rs/book/actix/sec-2-actor.html) simlar to [Akka](https://doc.akka.io/docs/akka/current/typed/actors.html) which seems like it could be well suited to performing aggregations and sorting in a more distributed manner.

#### **Error handling**

The solution I wrote works fairly well along the golden path when everything is operating normally. In a production system I would expect the incident APIs to return errors or need to be timed out if they take too long.

#### **Code organization**

The readability of this code can be greatly improved by moving more logic from webserver bin back into the shared library.

#### **Testing**

Closely related to enhancing error handling and breaking up the logic in the binary and library is writing test to prove the correctness of the code and also exploring more graceful error handling.

#### **Performance**

This solution has some ineffencies that would need to be cleaned up before running this in production. 

For instance, one corner I cut while writing this solition was to serialize and deseralize json in at least one place to get around Rust's borrow checker. 

Another is referencing environment variables on each HTTP request. Again, to get around Rust's borrow checker.

### Distributed system design

If I were running this code in production I would want to think about how I could cache the data at various steps and even pre-compute the data to make serving it up as fast as possible. 

For this particular solution I think it makes sense to have a retrieval system that hits the incident endpoints on some cadence, caches the raw API results in Redis, and then have the API portion either pull a precomputed result from Redis or compute the results on the fly.