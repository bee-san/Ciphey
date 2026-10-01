///! This is the struct used to design what a search node looks like.
///! At each level, we have a node with some text, T.
///! And then the edges of that node are the decryption modules.

/*struct Nodes<V> {
    /// When we expand the node, we generate children node
    /// This is an vector of children.
    children: Vec<Nodes<V>>,
    /// Value is the text we are using
    value: V
    /// Edges so far enables us to know the decryption route
    /// Because decryptions are edges, we can write the route like:
    /// vec!["Base64", "Base32", "Rot13"] and so on indicating it
    /// started from base64, then base32, and finally rot13.
    edges_so_far: Vec<&str>
}
*/