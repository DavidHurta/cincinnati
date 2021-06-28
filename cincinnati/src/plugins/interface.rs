// This file is generated by rust-protobuf 2.23.0. Do not edit
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_imports)]
#![allow(unused_results)]
//! Generated file from `src/plugins/interface.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
// const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_2_23_0;

#[derive(PartialEq,Clone,Default)]
pub struct Graph {
    // message fields
    pub nodes: ::protobuf::RepeatedField<Graph_Node>,
    pub edges: ::protobuf::RepeatedField<Graph_Edge>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a Graph {
    fn default() -> &'a Graph {
        <Graph as ::protobuf::Message>::default_instance()
    }
}

impl Graph {
    pub fn new() -> Graph {
        ::std::default::Default::default()
    }

    // repeated .Graph.Node nodes = 1;


    pub fn get_nodes(&self) -> &[Graph_Node] {
        &self.nodes
    }
    pub fn clear_nodes(&mut self) {
        self.nodes.clear();
    }

    // Param is passed by value, moved
    pub fn set_nodes(&mut self, v: ::protobuf::RepeatedField<Graph_Node>) {
        self.nodes = v;
    }

    // Mutable pointer to the field.
    pub fn mut_nodes(&mut self) -> &mut ::protobuf::RepeatedField<Graph_Node> {
        &mut self.nodes
    }

    // Take field
    pub fn take_nodes(&mut self) -> ::protobuf::RepeatedField<Graph_Node> {
        ::std::mem::replace(&mut self.nodes, ::protobuf::RepeatedField::new())
    }

    // repeated .Graph.Edge edges = 2;


    pub fn get_edges(&self) -> &[Graph_Edge] {
        &self.edges
    }
    pub fn clear_edges(&mut self) {
        self.edges.clear();
    }

    // Param is passed by value, moved
    pub fn set_edges(&mut self, v: ::protobuf::RepeatedField<Graph_Edge>) {
        self.edges = v;
    }

    // Mutable pointer to the field.
    pub fn mut_edges(&mut self) -> &mut ::protobuf::RepeatedField<Graph_Edge> {
        &mut self.edges
    }

    // Take field
    pub fn take_edges(&mut self) -> ::protobuf::RepeatedField<Graph_Edge> {
        ::std::mem::replace(&mut self.edges, ::protobuf::RepeatedField::new())
    }
}

impl ::protobuf::Message for Graph {
    fn is_initialized(&self) -> bool {
        for v in &self.nodes {
            if !v.is_initialized() {
                return false;
            }
        };
        for v in &self.edges {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_repeated_message_into(wire_type, is, &mut self.nodes)?;
                },
                2 => {
                    ::protobuf::rt::read_repeated_message_into(wire_type, is, &mut self.edges)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        for value in &self.nodes {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        };
        for value in &self.edges {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        for v in &self.nodes {
            os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        };
        for v in &self.edges {
            os.write_tag(2, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        };
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: ::std::boxed::Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> Graph {
        Graph::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<Graph_Node>>(
                "nodes",
                |m: &Graph| { &m.nodes },
                |m: &mut Graph| { &mut m.nodes },
            ));
            fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<Graph_Edge>>(
                "edges",
                |m: &Graph| { &m.edges },
                |m: &mut Graph| { &mut m.edges },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<Graph>(
                "Graph",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static Graph {
        static instance: ::protobuf::rt::LazyV2<Graph> = ::protobuf::rt::LazyV2::INIT;
        instance.get(Graph::new)
    }
}

impl ::protobuf::Clear for Graph {
    fn clear(&mut self) {
        self.nodes.clear();
        self.edges.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for Graph {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for Graph {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct Graph_Node {
    // message fields
    pub version: ::std::string::String,
    pub payload: ::std::string::String,
    pub metadata: ::std::collections::HashMap<::std::string::String, ::std::string::String>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a Graph_Node {
    fn default() -> &'a Graph_Node {
        <Graph_Node as ::protobuf::Message>::default_instance()
    }
}

impl Graph_Node {
    pub fn new() -> Graph_Node {
        ::std::default::Default::default()
    }

    // string version = 1;


    pub fn get_version(&self) -> &str {
        &self.version
    }
    pub fn clear_version(&mut self) {
        self.version.clear();
    }

    // Param is passed by value, moved
    pub fn set_version(&mut self, v: ::std::string::String) {
        self.version = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_version(&mut self) -> &mut ::std::string::String {
        &mut self.version
    }

    // Take field
    pub fn take_version(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.version, ::std::string::String::new())
    }

    // string payload = 2;


    pub fn get_payload(&self) -> &str {
        &self.payload
    }
    pub fn clear_payload(&mut self) {
        self.payload.clear();
    }

    // Param is passed by value, moved
    pub fn set_payload(&mut self, v: ::std::string::String) {
        self.payload = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_payload(&mut self) -> &mut ::std::string::String {
        &mut self.payload
    }

    // Take field
    pub fn take_payload(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.payload, ::std::string::String::new())
    }

    // repeated .Graph.Node.MetadataEntry metadata = 3;


    pub fn get_metadata(&self) -> &::std::collections::HashMap<::std::string::String, ::std::string::String> {
        &self.metadata
    }
    pub fn clear_metadata(&mut self) {
        self.metadata.clear();
    }

    // Param is passed by value, moved
    pub fn set_metadata(&mut self, v: ::std::collections::HashMap<::std::string::String, ::std::string::String>) {
        self.metadata = v;
    }

    // Mutable pointer to the field.
    pub fn mut_metadata(&mut self) -> &mut ::std::collections::HashMap<::std::string::String, ::std::string::String> {
        &mut self.metadata
    }

    // Take field
    pub fn take_metadata(&mut self) -> ::std::collections::HashMap<::std::string::String, ::std::string::String> {
        ::std::mem::replace(&mut self.metadata, ::std::collections::HashMap::new())
    }
}

impl ::protobuf::Message for Graph_Node {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.version)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.payload)?;
                },
                3 => {
                    ::protobuf::rt::read_map_into::<::protobuf::types::ProtobufTypeString, ::protobuf::types::ProtobufTypeString>(wire_type, is, &mut self.metadata)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if !self.version.is_empty() {
            my_size += ::protobuf::rt::string_size(1, &self.version);
        }
        if !self.payload.is_empty() {
            my_size += ::protobuf::rt::string_size(2, &self.payload);
        }
        my_size += ::protobuf::rt::compute_map_size::<::protobuf::types::ProtobufTypeString, ::protobuf::types::ProtobufTypeString>(3, &self.metadata);
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if !self.version.is_empty() {
            os.write_string(1, &self.version)?;
        }
        if !self.payload.is_empty() {
            os.write_string(2, &self.payload)?;
        }
        ::protobuf::rt::write_map_with_cached_sizes::<::protobuf::types::ProtobufTypeString, ::protobuf::types::ProtobufTypeString>(3, &self.metadata, os)?;
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: ::std::boxed::Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> Graph_Node {
        Graph_Node::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "version",
                |m: &Graph_Node| { &m.version },
                |m: &mut Graph_Node| { &mut m.version },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "payload",
                |m: &Graph_Node| { &m.payload },
                |m: &mut Graph_Node| { &mut m.payload },
            ));
            fields.push(::protobuf::reflect::accessor::make_map_accessor::<_, ::protobuf::types::ProtobufTypeString, ::protobuf::types::ProtobufTypeString>(
                "metadata",
                |m: &Graph_Node| { &m.metadata },
                |m: &mut Graph_Node| { &mut m.metadata },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<Graph_Node>(
                "Graph.Node",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static Graph_Node {
        static instance: ::protobuf::rt::LazyV2<Graph_Node> = ::protobuf::rt::LazyV2::INIT;
        instance.get(Graph_Node::new)
    }
}

impl ::protobuf::Clear for Graph_Node {
    fn clear(&mut self) {
        self.version.clear();
        self.payload.clear();
        self.metadata.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for Graph_Node {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for Graph_Node {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct Graph_Edge {
    // message fields
    pub from: u64,
    pub to: u64,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a Graph_Edge {
    fn default() -> &'a Graph_Edge {
        <Graph_Edge as ::protobuf::Message>::default_instance()
    }
}

impl Graph_Edge {
    pub fn new() -> Graph_Edge {
        ::std::default::Default::default()
    }

    // uint64 from = 1;


    pub fn get_from(&self) -> u64 {
        self.from
    }
    pub fn clear_from(&mut self) {
        self.from = 0;
    }

    // Param is passed by value, moved
    pub fn set_from(&mut self, v: u64) {
        self.from = v;
    }

    // uint64 to = 2;


    pub fn get_to(&self) -> u64 {
        self.to
    }
    pub fn clear_to(&mut self) {
        self.to = 0;
    }

    // Param is passed by value, moved
    pub fn set_to(&mut self, v: u64) {
        self.to = v;
    }
}

impl ::protobuf::Message for Graph_Edge {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint64()?;
                    self.from = tmp;
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint64()?;
                    self.to = tmp;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if self.from != 0 {
            my_size += ::protobuf::rt::value_size(1, self.from, ::protobuf::wire_format::WireTypeVarint);
        }
        if self.to != 0 {
            my_size += ::protobuf::rt::value_size(2, self.to, ::protobuf::wire_format::WireTypeVarint);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if self.from != 0 {
            os.write_uint64(1, self.from)?;
        }
        if self.to != 0 {
            os.write_uint64(2, self.to)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: ::std::boxed::Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> Graph_Edge {
        Graph_Edge::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeUint64>(
                "from",
                |m: &Graph_Edge| { &m.from },
                |m: &mut Graph_Edge| { &mut m.from },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeUint64>(
                "to",
                |m: &Graph_Edge| { &m.to },
                |m: &mut Graph_Edge| { &mut m.to },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<Graph_Edge>(
                "Graph.Edge",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static Graph_Edge {
        static instance: ::protobuf::rt::LazyV2<Graph_Edge> = ::protobuf::rt::LazyV2::INIT;
        instance.get(Graph_Edge::new)
    }
}

impl ::protobuf::Clear for Graph_Edge {
    fn clear(&mut self) {
        self.from = 0;
        self.to = 0;
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for Graph_Edge {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for Graph_Edge {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct PluginExchange {
    // message fields
    pub graph: ::protobuf::SingularPtrField<Graph>,
    pub parameters: ::std::collections::HashMap<::std::string::String, ::std::string::String>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a PluginExchange {
    fn default() -> &'a PluginExchange {
        <PluginExchange as ::protobuf::Message>::default_instance()
    }
}

impl PluginExchange {
    pub fn new() -> PluginExchange {
        ::std::default::Default::default()
    }

    // .Graph graph = 1;


    pub fn get_graph(&self) -> &Graph {
        self.graph.as_ref().unwrap_or_else(|| <Graph as ::protobuf::Message>::default_instance())
    }
    pub fn clear_graph(&mut self) {
        self.graph.clear();
    }

    pub fn has_graph(&self) -> bool {
        self.graph.is_some()
    }

    // Param is passed by value, moved
    pub fn set_graph(&mut self, v: Graph) {
        self.graph = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_graph(&mut self) -> &mut Graph {
        if self.graph.is_none() {
            self.graph.set_default();
        }
        self.graph.as_mut().unwrap()
    }

    // Take field
    pub fn take_graph(&mut self) -> Graph {
        self.graph.take().unwrap_or_else(|| Graph::new())
    }

    // repeated .PluginExchange.ParametersEntry parameters = 2;


    pub fn get_parameters(&self) -> &::std::collections::HashMap<::std::string::String, ::std::string::String> {
        &self.parameters
    }
    pub fn clear_parameters(&mut self) {
        self.parameters.clear();
    }

    // Param is passed by value, moved
    pub fn set_parameters(&mut self, v: ::std::collections::HashMap<::std::string::String, ::std::string::String>) {
        self.parameters = v;
    }

    // Mutable pointer to the field.
    pub fn mut_parameters(&mut self) -> &mut ::std::collections::HashMap<::std::string::String, ::std::string::String> {
        &mut self.parameters
    }

    // Take field
    pub fn take_parameters(&mut self) -> ::std::collections::HashMap<::std::string::String, ::std::string::String> {
        ::std::mem::replace(&mut self.parameters, ::std::collections::HashMap::new())
    }
}

impl ::protobuf::Message for PluginExchange {
    fn is_initialized(&self) -> bool {
        for v in &self.graph {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.graph)?;
                },
                2 => {
                    ::protobuf::rt::read_map_into::<::protobuf::types::ProtobufTypeString, ::protobuf::types::ProtobufTypeString>(wire_type, is, &mut self.parameters)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.graph.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        my_size += ::protobuf::rt::compute_map_size::<::protobuf::types::ProtobufTypeString, ::protobuf::types::ProtobufTypeString>(2, &self.parameters);
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.graph.as_ref() {
            os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        ::protobuf::rt::write_map_with_cached_sizes::<::protobuf::types::ProtobufTypeString, ::protobuf::types::ProtobufTypeString>(2, &self.parameters, os)?;
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: ::std::boxed::Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> PluginExchange {
        PluginExchange::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<Graph>>(
                "graph",
                |m: &PluginExchange| { &m.graph },
                |m: &mut PluginExchange| { &mut m.graph },
            ));
            fields.push(::protobuf::reflect::accessor::make_map_accessor::<_, ::protobuf::types::ProtobufTypeString, ::protobuf::types::ProtobufTypeString>(
                "parameters",
                |m: &PluginExchange| { &m.parameters },
                |m: &mut PluginExchange| { &mut m.parameters },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<PluginExchange>(
                "PluginExchange",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static PluginExchange {
        static instance: ::protobuf::rt::LazyV2<PluginExchange> = ::protobuf::rt::LazyV2::INIT;
        instance.get(PluginExchange::new)
    }
}

impl ::protobuf::Clear for PluginExchange {
    fn clear(&mut self) {
        self.graph.clear();
        self.parameters.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for PluginExchange {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for PluginExchange {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct PluginError {
    // message fields
    pub kind: PluginError_Kind,
    pub value: ::std::string::String,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a PluginError {
    fn default() -> &'a PluginError {
        <PluginError as ::protobuf::Message>::default_instance()
    }
}

impl PluginError {
    pub fn new() -> PluginError {
        ::std::default::Default::default()
    }

    // .PluginError.Kind kind = 1;


    pub fn get_kind(&self) -> PluginError_Kind {
        self.kind
    }
    pub fn clear_kind(&mut self) {
        self.kind = PluginError_Kind::GENERIC;
    }

    // Param is passed by value, moved
    pub fn set_kind(&mut self, v: PluginError_Kind) {
        self.kind = v;
    }

    // string value = 2;


    pub fn get_value(&self) -> &str {
        &self.value
    }
    pub fn clear_value(&mut self) {
        self.value.clear();
    }

    // Param is passed by value, moved
    pub fn set_value(&mut self, v: ::std::string::String) {
        self.value = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_value(&mut self) -> &mut ::std::string::String {
        &mut self.value
    }

    // Take field
    pub fn take_value(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.value, ::std::string::String::new())
    }
}

impl ::protobuf::Message for PluginError {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_proto3_enum_with_unknown_fields_into(wire_type, is, &mut self.kind, 1, &mut self.unknown_fields)?
                },
                2 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.value)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if self.kind != PluginError_Kind::GENERIC {
            my_size += ::protobuf::rt::enum_size(1, self.kind);
        }
        if !self.value.is_empty() {
            my_size += ::protobuf::rt::string_size(2, &self.value);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if self.kind != PluginError_Kind::GENERIC {
            os.write_enum(1, ::protobuf::ProtobufEnum::value(&self.kind))?;
        }
        if !self.value.is_empty() {
            os.write_string(2, &self.value)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: ::std::boxed::Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> PluginError {
        PluginError::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeEnum<PluginError_Kind>>(
                "kind",
                |m: &PluginError| { &m.kind },
                |m: &mut PluginError| { &mut m.kind },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "value",
                |m: &PluginError| { &m.value },
                |m: &mut PluginError| { &mut m.value },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<PluginError>(
                "PluginError",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static PluginError {
        static instance: ::protobuf::rt::LazyV2<PluginError> = ::protobuf::rt::LazyV2::INIT;
        instance.get(PluginError::new)
    }
}

impl ::protobuf::Clear for PluginError {
    fn clear(&mut self) {
        self.kind = PluginError_Kind::GENERIC;
        self.value.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for PluginError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for PluginError {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

#[derive(Clone,PartialEq,Eq,Debug,Hash)]
pub enum PluginError_Kind {
    GENERIC = 0,
    INVALID_GRAPH = 1,
    INVALID_PARAM = 2,
    FAILED_DEPENDENCY = 3,
    INTERNAL_FAILURE = 4,
}

impl ::protobuf::ProtobufEnum for PluginError_Kind {
    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> ::std::option::Option<PluginError_Kind> {
        match value {
            0 => ::std::option::Option::Some(PluginError_Kind::GENERIC),
            1 => ::std::option::Option::Some(PluginError_Kind::INVALID_GRAPH),
            2 => ::std::option::Option::Some(PluginError_Kind::INVALID_PARAM),
            3 => ::std::option::Option::Some(PluginError_Kind::FAILED_DEPENDENCY),
            4 => ::std::option::Option::Some(PluginError_Kind::INTERNAL_FAILURE),
            _ => ::std::option::Option::None
        }
    }

    fn values() -> &'static [Self] {
        static values: &'static [PluginError_Kind] = &[
            PluginError_Kind::GENERIC,
            PluginError_Kind::INVALID_GRAPH,
            PluginError_Kind::INVALID_PARAM,
            PluginError_Kind::FAILED_DEPENDENCY,
            PluginError_Kind::INTERNAL_FAILURE,
        ];
        values
    }

    fn enum_descriptor_static() -> &'static ::protobuf::reflect::EnumDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::EnumDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            ::protobuf::reflect::EnumDescriptor::new_pb_name::<PluginError_Kind>("PluginError.Kind", file_descriptor_proto())
        })
    }
}

impl ::std::marker::Copy for PluginError_Kind {
}

impl ::std::default::Default for PluginError_Kind {
    fn default() -> Self {
        PluginError_Kind::GENERIC
    }
}

impl ::protobuf::reflect::ProtobufValue for PluginError_Kind {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Enum(::protobuf::ProtobufEnum::descriptor(self))
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x1bsrc/plugins/interface.proto\"\xaa\x02\n\x05Graph\x12!\n\x05nodes\
    \x18\x01\x20\x03(\x0b2\x0b.Graph.NodeR\x05nodes\x12!\n\x05edges\x18\x02\
    \x20\x03(\x0b2\x0b.Graph.EdgeR\x05edges\x1a\xae\x01\n\x04Node\x12\x18\n\
    \x07version\x18\x01\x20\x01(\tR\x07version\x12\x18\n\x07payload\x18\x02\
    \x20\x01(\tR\x07payload\x125\n\x08metadata\x18\x03\x20\x03(\x0b2\x19.Gra\
    ph.Node.MetadataEntryR\x08metadata\x1a;\n\rMetadataEntry\x12\x10\n\x03ke\
    y\x18\x01\x20\x01(\tR\x03key\x12\x14\n\x05value\x18\x02\x20\x01(\tR\x05v\
    alue:\x028\x01\x1a*\n\x04Edge\x12\x12\n\x04from\x18\x01\x20\x01(\x04R\
    \x04from\x12\x0e\n\x02to\x18\x02\x20\x01(\x04R\x02to\"\xae\x01\n\x0ePlug\
    inExchange\x12\x1c\n\x05graph\x18\x01\x20\x01(\x0b2\x06.GraphR\x05graph\
    \x12?\n\nparameters\x18\x02\x20\x03(\x0b2\x1f.PluginExchange.ParametersE\
    ntryR\nparameters\x1a=\n\x0fParametersEntry\x12\x10\n\x03key\x18\x01\x20\
    \x01(\tR\x03key\x12\x14\n\x05value\x18\x02\x20\x01(\tR\x05value:\x028\
    \x01\"\xb2\x01\n\x0bPluginError\x12%\n\x04kind\x18\x01\x20\x01(\x0e2\x11\
    .PluginError.KindR\x04kind\x12\x14\n\x05value\x18\x02\x20\x01(\tR\x05val\
    ue\"f\n\x04Kind\x12\x0b\n\x07GENERIC\x10\0\x12\x11\n\rINVALID_GRAPH\x10\
    \x01\x12\x11\n\rINVALID_PARAM\x10\x02\x12\x15\n\x11FAILED_DEPENDENCY\x10\
    \x03\x12\x14\n\x10INTERNAL_FAILURE\x10\x04b\x06proto3\
";

static file_descriptor_proto_lazy: ::protobuf::rt::LazyV2<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::rt::LazyV2::INIT;

fn parse_descriptor_proto() -> ::protobuf::descriptor::FileDescriptorProto {
    ::protobuf::Message::parse_from_bytes(file_descriptor_proto_data).unwrap()
}

pub fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    file_descriptor_proto_lazy.get(|| {
        parse_descriptor_proto()
    })
}
