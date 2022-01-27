/*
Copyright 2021 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package env

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsinstall "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	jsonserializer "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/runtime/serializer/versioning"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// internalScheme is an internal scheme that understands CRDs and meta
	// objects so env can convert these object types.
	internalScheme = runtime.NewScheme()
)

func init() {
	// Register meta and CRD/extension schemes to we can operator parse CRDs.
	utilruntime.Must(metav1.AddMetaToScheme(internalScheme))
	utilruntime.Must(extapi.AddToScheme(internalScheme))
	apiextensionsinstall.Install(internalScheme)
}

// readCRDsAtDirectories will read all CRDs yaml manifests files at the given
// directories, parses and converts them into CustomResourceDefinition objects.
func readCRDsAtDirectories(t *testing.T, dirs ...string) []*apiextensionsv1.CustomResourceDefinition {
	serializer := jsonserializer.NewSerializerWithOptions(jsonserializer.DefaultMetaFactory, internalScheme, internalScheme, jsonserializer.SerializerOptions{
		Yaml: true,
	})
	converter := runtime.UnsafeObjectConvertor(internalScheme)
	codec := versioning.NewCodec(serializer, serializer, converter,
		internalScheme, internalScheme, internalScheme,
		runtime.InternalGroupVersioner, runtime.InternalGroupVersioner,
		internalScheme.Name(),
	)

	var crds []*apiextensionsv1.CustomResourceDefinition
	for _, dir := range dirs {
		if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Ignore non-YAML files.
			if filepath.Ext(path) != ".yaml" {
				return nil
			}

			crd, err := readCRDsAtFilePath(codec, converter, path)
			if err != nil {
				return err
			}
			crds = append(crds, crd...)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	return crds
}

// readCRDsAtFilePath will attempt to read and parse CustomResourceDefinitions
// which are defined in the given file path location. Ignores empty or
// non-named CRD definitions.
func readCRDsAtFilePath(codec runtime.Codec, converter runtime.ObjectConvertor, path string) ([]*apiextensionsv1.CustomResourceDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var crds []*apiextensionsv1.CustomResourceDefinition
	for _, d := range strings.Split(string(data), "\n---\n") {
		// skip empty YAML documents
		if strings.TrimSpace(d) == "" {
			continue
		}

		var internalCRD apiextensions.CustomResourceDefinition
		if _, _, err := codec.Decode([]byte(d), nil, &internalCRD); err != nil {
			return nil, err
		}

		var out apiextensionsv1.CustomResourceDefinition
		if err := converter.Convert(&internalCRD, &out, nil); err != nil {
			return nil, err
		}

		// Skip CRDs which don't have a name.
		if out.Name == "" {
			continue
		}

		crds = append(crds, &out)
	}

	return crds, nil
}

// crdsToRuntimeObjects coverts the CustomResourceDefinition object into
// generic controller-runtime client.Objects
func crdsToRuntimeObjects(in []*apiextensionsv1.CustomResourceDefinition) []client.Object {
	out := make([]client.Object, len(in))

	for i := range in {
		out[i] = client.Object(in[i])
	}

	return out
}
