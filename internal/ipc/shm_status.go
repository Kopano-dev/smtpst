/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package ipc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"bitbucket.org/avd/go-ipc/mmf"
	"bitbucket.org/avd/go-ipc/shm"

	"stash.kopano.io/kgol/smtpst/server"
)

const (
	shmStatusProjectID  = "smtpstd"
	shmStatusTotalSize  = 1024 * 1024 // 1 MiB
	shmStatusHeaderSize = 128
	shmStatusVersion1   = uint8(1)
)

func ftok(s, id string) string {
	h := sha256.New()
	h.Write([]byte(s))
	h.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:8])
}

type shmStatus struct {
	statePath string
	projectID string
}

func (s *shmStatus) ftok() string {
	if s.statePath == "" {
		panic("no state path set")
	}
	projectID := s.projectID
	if projectID == "" {
		projectID = shmStatusProjectID
	}
	return projectID + "-status." + ftok(s.statePath, projectID)
}

func (s *shmStatus) clear() error {
	name := s.ftok()

	return shm.DestroyMemoryObject(name)
}

func (s *shmStatus) set(status *server.Status) error {
	payload, shmErr := json.Marshal(status)
	if shmErr != nil {
		return fmt.Errorf("failed to encode status: %w", shmErr)
	}
	signature := sha256.Sum256(payload)

	name := s.ftok()

	obj, _, shmErr := shm.NewMemoryObjectSize(name, os.O_CREATE|os.O_WRONLY, 0666, shmStatusTotalSize)
	if shmErr != nil {
		return fmt.Errorf("failed to open shm for status: %w", shmErr)
	}

	// Header (start at byte 1, little endian)
	// 1 byte version (uint8)
	// 4 byte payload lengh (uint32)
	//
	// Payload (start at byte 128)
	// .. as long as payload length says
	// 32 byte payload sha256 signature

	headerRegion, shmErr := mmf.NewMemoryRegion(obj, mmf.MEM_READWRITE, 0, shmStatusTotalSize)
	if shmErr != nil {
		return fmt.Errorf("failed to open mmf status header: %w", shmErr)
	}
	defer headerRegion.Close()

	payloadRegion, shmErr := mmf.NewMemoryRegion(obj, mmf.MEM_READWRITE, shmStatusHeaderSize, shmStatusTotalSize-shmStatusHeaderSize)
	if shmErr != nil {
		return fmt.Errorf("failed to open mmf status payload: %w", shmErr)
	}
	defer payloadRegion.Close()

	headerWriter := mmf.NewMemoryRegionWriter(headerRegion)
	payloadWriter := mmf.NewMemoryRegionWriter(payloadRegion)

	// Update payload first.

	n, shmErr := payloadWriter.Write(payload)
	if shmErr == nil && n != len(payload) {
		shmErr = fmt.Errorf("short write")
	}
	if shmErr != nil {
		return fmt.Errorf("failed to write status mmf: %w", shmErr)
	}

	if flushErr := payloadRegion.Flush(false); flushErr != nil {
		return flushErr
	}

	// Update header.

	shmErr = binary.Write(headerWriter, binary.LittleEndian, shmStatusVersion1)
	if shmErr != nil {
		return fmt.Errorf("failed to write status header version mmf: %w", shmErr)
	}

	shmErr = binary.Write(headerWriter, binary.LittleEndian, uint32(len(payload)))
	if shmErr != nil {
		return fmt.Errorf("failed to write status mmf: %w", shmErr)
	}

	if flushErr := headerRegion.Flush(false); flushErr != nil {
		return flushErr
	}

	// Update signature last.

	n, shmErr = payloadWriter.WriteAt(signature[:], int64(len(payload)))
	if shmErr == nil && n != len(signature) {
		shmErr = fmt.Errorf("short write")
	}
	if shmErr != nil {
		return fmt.Errorf("failed to write status signature mmf: %w", shmErr)
	}

	if flushErr := payloadRegion.Flush(false); flushErr != nil {
		return flushErr
	}

	return nil
}

func (s *shmStatus) get() (*server.Status, error) {
	name := s.ftok()

	obj, shmErr := shm.NewMemoryObject(name, os.O_RDONLY, 0666)
	if shmErr != nil {
		return nil, fmt.Errorf("failed to read shm for status: %w", shmErr)
	}

	headerRegion, shmErr := mmf.NewMemoryRegion(obj, mmf.MEM_READ_ONLY, 0, shmStatusTotalSize)
	if shmErr != nil {
		return nil, fmt.Errorf("failed to read mmf status header: %w", shmErr)
	}
	defer headerRegion.Close()

	headerReader := mmf.NewMemoryRegionReader(headerRegion)

	var version uint8
	shmErr = binary.Read(headerReader, binary.LittleEndian, &version)
	if shmErr != nil {
		return nil, fmt.Errorf("failed to read mmf status header version: %w", shmErr)
	}

	var payloadReader io.Reader
	var status *server.Status

	switch version {
	case shmStatusVersion1:
		var payloadSize uint32
		mmfErr := binary.Read(headerReader, binary.LittleEndian, &payloadSize)
		if mmfErr != nil {
			return nil, fmt.Errorf("failed to read mmf status header payload size: %w", mmfErr)
		}

		payloadRegion, mmfErr := mmf.NewMemoryRegion(obj, mmf.MEM_READ_ONLY, shmStatusHeaderSize, shmStatusTotalSize-shmStatusHeaderSize)
		if mmfErr != nil {
			return nil, fmt.Errorf("failed to read mmf status payload: %w", mmfErr)
		}
		defer payloadRegion.Close()

		payloadReader = io.LimitReader(mmf.NewMemoryRegionReader(payloadRegion), int64(payloadSize))

		payload, mmfErr := io.ReadAll(payloadReader)
		if mmfErr != nil {
			return nil, fmt.Errorf("failed to read mmf status payload data: %w", mmfErr)
		}
		if uint32(len(payload)) != payloadSize {
			return nil, fmt.Errorf("invalid payload size")
		}

		signatureA := sha256.Sum256(payload)

		signatureRegion, mmfErr := mmf.NewMemoryRegion(obj, mmf.MEM_READ_ONLY, shmStatusHeaderSize+int64(payloadSize), len(signatureA))
		if mmfErr != nil {
			return nil, fmt.Errorf("failed to read mmf status payload signature: %w", mmfErr)
		}

		signatureReader := io.LimitReader(mmf.NewMemoryRegionReader(signatureRegion), int64(len(signatureA)))
		signatureB, mmfErr := io.ReadAll(signatureReader)
		if mmfErr != nil {
			return nil, fmt.Errorf("failed to read mmf status payload signature data: %w", mmfErr)
		}

		if !bytes.Equal(signatureA[:], signatureB) {
			return nil, fmt.Errorf("signature mismatch: %s, %s, %s", string(payload), signatureA, signatureB)
		}

		status = &server.Status{}
		mmfErr = json.Unmarshal(payload, status)
		if mmfErr != nil {
			return nil, fmt.Errorf("failed to read status mmf: %w", mmfErr)
		}

	default:
		return nil, fmt.Errorf("unknown mmf status header version: %v", version)
	}

	return status, nil
}
