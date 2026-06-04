package wg

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

// kernelBackend creates WireGuard links using the in-kernel WireGuard module via
// netlink. Creating a link of type "wireguard" autoloads the kernel module.
type kernelBackend struct{}

// Ensure creates the WireGuard link if it does not exist yet. It is idempotent:
// an already-present link, or a concurrent creation, is treated as success.
func (kernelBackend) Ensure(name string) error {
	if _, err := netlink.LinkByName(name); err == nil {
		return nil
	}
	link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(link); err != nil {
		if _, lookupErr := netlink.LinkByName(name); lookupErr == nil {
			return nil
		}
		return fmt.Errorf("create wireguard link %q: %w", name, err)
	}
	return nil
}

// Remove deletes the WireGuard link if present. A missing link is not an error.
func (kernelBackend) Remove(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("delete wireguard link %q: %w", name, err)
	}
	return nil
}
