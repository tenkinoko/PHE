// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.18.1
// source: phe/phe.proto

package phe

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type SetupC struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Flag []byte `protobuf:"bytes,1,opt,name=flag,proto3" json:"flag,omitempty"`
}

func (x *SetupC) Reset() {
	*x = SetupC{}
	if protoimpl.UnsafeEnabled {
		mi := &file_phe_phe_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SetupC) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SetupC) ProtoMessage() {}

func (x *SetupC) ProtoReflect() protoreflect.Message {
	mi := &file_phe_phe_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SetupC.ProtoReflect.Descriptor instead.
func (*SetupC) Descriptor() ([]byte, []int) {
	return file_phe_phe_proto_rawDescGZIP(), []int{0}
}

func (x *SetupC) GetFlag() []byte {
	if x != nil {
		return x.Flag
	}
	return nil
}

type SetupS struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	H []byte `protobuf:"bytes,1,opt,name=h,proto3" json:"h,omitempty"`
	Z []byte `protobuf:"bytes,2,opt,name=z,proto3" json:"z,omitempty"`
}

func (x *SetupS) Reset() {
	*x = SetupS{}
	if protoimpl.UnsafeEnabled {
		mi := &file_phe_phe_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SetupS) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SetupS) ProtoMessage() {}

func (x *SetupS) ProtoReflect() protoreflect.Message {
	mi := &file_phe_phe_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SetupS.ProtoReflect.Descriptor instead.
func (*SetupS) Descriptor() ([]byte, []int) {
	return file_phe_phe_proto_rawDescGZIP(), []int{1}
}

func (x *SetupS) GetH() []byte {
	if x != nil {
		return x.H
	}
	return nil
}

func (x *SetupS) GetZ() []byte {
	if x != nil {
		return x.Z
	}
	return nil
}

type EnrollmentC struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Un []byte `protobuf:"bytes,1,opt,name=un,proto3" json:"un,omitempty"`
}

func (x *EnrollmentC) Reset() {
	*x = EnrollmentC{}
	if protoimpl.UnsafeEnabled {
		mi := &file_phe_phe_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnrollmentC) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnrollmentC) ProtoMessage() {}

func (x *EnrollmentC) ProtoReflect() protoreflect.Message {
	mi := &file_phe_phe_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnrollmentC.ProtoReflect.Descriptor instead.
func (*EnrollmentC) Descriptor() ([]byte, []int) {
	return file_phe_phe_proto_rawDescGZIP(), []int{2}
}

func (x *EnrollmentC) GetUn() []byte {
	if x != nil {
		return x.Un
	}
	return nil
}

type EnrollmentS struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hs []byte `protobuf:"bytes,1,opt,name=hs,proto3" json:"hs,omitempty"`
	Ns []byte `protobuf:"bytes,2,opt,name=ns,proto3" json:"ns,omitempty"`
}

func (x *EnrollmentS) Reset() {
	*x = EnrollmentS{}
	if protoimpl.UnsafeEnabled {
		mi := &file_phe_phe_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnrollmentS) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnrollmentS) ProtoMessage() {}

func (x *EnrollmentS) ProtoReflect() protoreflect.Message {
	mi := &file_phe_phe_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnrollmentS.ProtoReflect.Descriptor instead.
func (*EnrollmentS) Descriptor() ([]byte, []int) {
	return file_phe_phe_proto_rawDescGZIP(), []int{3}
}

func (x *EnrollmentS) GetHs() []byte {
	if x != nil {
		return x.Hs
	}
	return nil
}

func (x *EnrollmentS) GetNs() []byte {
	if x != nil {
		return x.Ns
	}
	return nil
}

type ValidationC struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	C1 []byte `protobuf:"bytes,1,opt,name=c1,proto3" json:"c1,omitempty"`
	C2 []byte `protobuf:"bytes,2,opt,name=c2,proto3" json:"c2,omitempty"`
	C3 []byte `protobuf:"bytes,3,opt,name=c3,proto3" json:"c3,omitempty"`
}

func (x *ValidationC) Reset() {
	*x = ValidationC{}
	if protoimpl.UnsafeEnabled {
		mi := &file_phe_phe_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ValidationC) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ValidationC) ProtoMessage() {}

func (x *ValidationC) ProtoReflect() protoreflect.Message {
	mi := &file_phe_phe_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ValidationC.ProtoReflect.Descriptor instead.
func (*ValidationC) Descriptor() ([]byte, []int) {
	return file_phe_phe_proto_rawDescGZIP(), []int{4}
}

func (x *ValidationC) GetC1() []byte {
	if x != nil {
		return x.C1
	}
	return nil
}

func (x *ValidationC) GetC2() []byte {
	if x != nil {
		return x.C2
	}
	return nil
}

func (x *ValidationC) GetC3() []byte {
	if x != nil {
		return x.C3
	}
	return nil
}

type ValidationS struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Flag bool `protobuf:"varint,1,opt,name=flag,proto3" json:"flag,omitempty"`
}

func (x *ValidationS) Reset() {
	*x = ValidationS{}
	if protoimpl.UnsafeEnabled {
		mi := &file_phe_phe_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ValidationS) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ValidationS) ProtoMessage() {}

func (x *ValidationS) ProtoReflect() protoreflect.Message {
	mi := &file_phe_phe_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ValidationS.ProtoReflect.Descriptor instead.
func (*ValidationS) Descriptor() ([]byte, []int) {
	return file_phe_phe_proto_rawDescGZIP(), []int{5}
}

func (x *ValidationS) GetFlag() bool {
	if x != nil {
		return x.Flag
	}
	return false
}

type RotationC struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Flag []byte `protobuf:"bytes,1,opt,name=flag,proto3" json:"flag,omitempty"`
}

func (x *RotationC) Reset() {
	*x = RotationC{}
	if protoimpl.UnsafeEnabled {
		mi := &file_phe_phe_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RotationC) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RotationC) ProtoMessage() {}

func (x *RotationC) ProtoReflect() protoreflect.Message {
	mi := &file_phe_phe_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RotationC.ProtoReflect.Descriptor instead.
func (*RotationC) Descriptor() ([]byte, []int) {
	return file_phe_phe_proto_rawDescGZIP(), []int{6}
}

func (x *RotationC) GetFlag() []byte {
	if x != nil {
		return x.Flag
	}
	return nil
}

type RotationS struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Alpha []byte `protobuf:"bytes,1,opt,name=alpha,proto3" json:"alpha,omitempty"`
	Beta  []byte `protobuf:"bytes,2,opt,name=beta,proto3" json:"beta,omitempty"`
	Gamma []byte `protobuf:"bytes,3,opt,name=gamma,proto3" json:"gamma,omitempty"`
	Zeta  []byte `protobuf:"bytes,4,opt,name=zeta,proto3" json:"zeta,omitempty"`
}

func (x *RotationS) Reset() {
	*x = RotationS{}
	if protoimpl.UnsafeEnabled {
		mi := &file_phe_phe_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RotationS) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RotationS) ProtoMessage() {}

func (x *RotationS) ProtoReflect() protoreflect.Message {
	mi := &file_phe_phe_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RotationS.ProtoReflect.Descriptor instead.
func (*RotationS) Descriptor() ([]byte, []int) {
	return file_phe_phe_proto_rawDescGZIP(), []int{7}
}

func (x *RotationS) GetAlpha() []byte {
	if x != nil {
		return x.Alpha
	}
	return nil
}

func (x *RotationS) GetBeta() []byte {
	if x != nil {
		return x.Beta
	}
	return nil
}

func (x *RotationS) GetGamma() []byte {
	if x != nil {
		return x.Gamma
	}
	return nil
}

func (x *RotationS) GetZeta() []byte {
	if x != nil {
		return x.Zeta
	}
	return nil
}

var File_phe_phe_proto protoreflect.FileDescriptor

var file_phe_phe_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x70, 0x68, 0x65, 0x2f, 0x70, 0x68, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x03, 0x70, 0x68, 0x65, 0x22, 0x1c, 0x0a, 0x06, 0x53, 0x65, 0x74, 0x75, 0x70, 0x43, 0x12, 0x12,
	0x0a, 0x04, 0x66, 0x6c, 0x61, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x66, 0x6c,
	0x61, 0x67, 0x22, 0x24, 0x0a, 0x06, 0x53, 0x65, 0x74, 0x75, 0x70, 0x53, 0x12, 0x0c, 0x0a, 0x01,
	0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x68, 0x12, 0x0c, 0x0a, 0x01, 0x7a, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x7a, 0x22, 0x1d, 0x0a, 0x0b, 0x45, 0x6e, 0x72, 0x6f,
	0x6c, 0x6c, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x12, 0x0e, 0x0a, 0x02, 0x75, 0x6e, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x02, 0x75, 0x6e, 0x22, 0x2d, 0x0a, 0x0b, 0x45, 0x6e, 0x72, 0x6f, 0x6c,
	0x6c, 0x6d, 0x65, 0x6e, 0x74, 0x53, 0x12, 0x0e, 0x0a, 0x02, 0x68, 0x73, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x02, 0x68, 0x73, 0x12, 0x0e, 0x0a, 0x02, 0x6e, 0x73, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x02, 0x6e, 0x73, 0x22, 0x3d, 0x0a, 0x0b, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x43, 0x12, 0x0e, 0x0a, 0x02, 0x63, 0x31, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x02, 0x63, 0x31, 0x12, 0x0e, 0x0a, 0x02, 0x63, 0x32, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x02, 0x63, 0x32, 0x12, 0x0e, 0x0a, 0x02, 0x63, 0x33, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x02, 0x63, 0x33, 0x22, 0x21, 0x0a, 0x0b, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x53, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x6c, 0x61, 0x67, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x04, 0x66, 0x6c, 0x61, 0x67, 0x22, 0x1f, 0x0a, 0x09, 0x52, 0x6f, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x43, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x6c, 0x61, 0x67, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x04, 0x66, 0x6c, 0x61, 0x67, 0x22, 0x5f, 0x0a, 0x09, 0x52, 0x6f, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x12, 0x14, 0x0a, 0x05, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x12, 0x12, 0x0a, 0x04,
	0x62, 0x65, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x62, 0x65, 0x74, 0x61,
	0x12, 0x14, 0x0a, 0x05, 0x67, 0x61, 0x6d, 0x6d, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x05, 0x67, 0x61, 0x6d, 0x6d, 0x61, 0x12, 0x12, 0x0a, 0x04, 0x7a, 0x65, 0x74, 0x61, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x7a, 0x65, 0x74, 0x61, 0x32, 0xc9, 0x01, 0x0a, 0x0c, 0x70,
	0x68, 0x65, 0x5f, 0x77, 0x6f, 0x72, 0x6b, 0x66, 0x6c, 0x6f, 0x77, 0x12, 0x23, 0x0a, 0x05, 0x53,
	0x65, 0x74, 0x75, 0x70, 0x12, 0x0b, 0x2e, 0x70, 0x68, 0x65, 0x2e, 0x53, 0x65, 0x74, 0x75, 0x70,
	0x43, 0x1a, 0x0b, 0x2e, 0x70, 0x68, 0x65, 0x2e, 0x53, 0x65, 0x74, 0x75, 0x70, 0x53, 0x22, 0x00,
	0x12, 0x32, 0x0a, 0x0a, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x10,
	0x2e, 0x70, 0x68, 0x65, 0x2e, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x6d, 0x65, 0x6e, 0x74, 0x43,
	0x1a, 0x10, 0x2e, 0x70, 0x68, 0x65, 0x2e, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x6d, 0x65, 0x6e,
	0x74, 0x53, 0x22, 0x00, 0x12, 0x32, 0x0a, 0x0a, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x12, 0x10, 0x2e, 0x70, 0x68, 0x65, 0x2e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x43, 0x1a, 0x10, 0x2e, 0x70, 0x68, 0x65, 0x2e, 0x56, 0x61, 0x6c, 0x69, 0x64,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x22, 0x00, 0x12, 0x2c, 0x0a, 0x08, 0x52, 0x6f, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0e, 0x2e, 0x70, 0x68, 0x65, 0x2e, 0x52, 0x6f, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x43, 0x1a, 0x0e, 0x2e, 0x70, 0x68, 0x65, 0x2e, 0x52, 0x6f, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x53, 0x22, 0x00, 0x42, 0x08, 0x5a, 0x06, 0x2e, 0x2e, 0x2f, 0x70, 0x68, 0x65,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_phe_phe_proto_rawDescOnce sync.Once
	file_phe_phe_proto_rawDescData = file_phe_phe_proto_rawDesc
)

func file_phe_phe_proto_rawDescGZIP() []byte {
	file_phe_phe_proto_rawDescOnce.Do(func() {
		file_phe_phe_proto_rawDescData = protoimpl.X.CompressGZIP(file_phe_phe_proto_rawDescData)
	})
	return file_phe_phe_proto_rawDescData
}

var file_phe_phe_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_phe_phe_proto_goTypes = []interface{}{
	(*SetupC)(nil),      // 0: phe.SetupC
	(*SetupS)(nil),      // 1: phe.SetupS
	(*EnrollmentC)(nil), // 2: phe.EnrollmentC
	(*EnrollmentS)(nil), // 3: phe.EnrollmentS
	(*ValidationC)(nil), // 4: phe.ValidationC
	(*ValidationS)(nil), // 5: phe.ValidationS
	(*RotationC)(nil),   // 6: phe.RotationC
	(*RotationS)(nil),   // 7: phe.RotationS
}
var file_phe_phe_proto_depIdxs = []int32{
	0, // 0: phe.phe_workflow.Setup:input_type -> phe.SetupC
	2, // 1: phe.phe_workflow.Enrollment:input_type -> phe.EnrollmentC
	4, // 2: phe.phe_workflow.Validation:input_type -> phe.ValidationC
	6, // 3: phe.phe_workflow.Rotation:input_type -> phe.RotationC
	1, // 4: phe.phe_workflow.Setup:output_type -> phe.SetupS
	3, // 5: phe.phe_workflow.Enrollment:output_type -> phe.EnrollmentS
	5, // 6: phe.phe_workflow.Validation:output_type -> phe.ValidationS
	7, // 7: phe.phe_workflow.Rotation:output_type -> phe.RotationS
	4, // [4:8] is the sub-list for method output_type
	0, // [0:4] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_phe_phe_proto_init() }
func file_phe_phe_proto_init() {
	if File_phe_phe_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_phe_phe_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SetupC); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_phe_phe_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SetupS); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_phe_phe_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EnrollmentC); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_phe_phe_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EnrollmentS); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_phe_phe_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ValidationC); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_phe_phe_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ValidationS); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_phe_phe_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RotationC); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_phe_phe_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RotationS); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_phe_phe_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_phe_phe_proto_goTypes,
		DependencyIndexes: file_phe_phe_proto_depIdxs,
		MessageInfos:      file_phe_phe_proto_msgTypes,
	}.Build()
	File_phe_phe_proto = out.File
	file_phe_phe_proto_rawDesc = nil
	file_phe_phe_proto_goTypes = nil
	file_phe_phe_proto_depIdxs = nil
}
