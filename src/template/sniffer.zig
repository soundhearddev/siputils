const std = @import("std");
const linux = std.os.linux;
const sip = @import("sip");

const utils = @import("siputils");
const registry = utils.registry;

const MAGIC: u8 = 0xA9;
const DISCOVERY_HEADER_SIZE: usize = 34;
const ETH_HLEN: usize = 14;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_ALL: u16 = 0x0003;
const IPPROTO_TCP: u8 = 6;
const AF_PACKET: u16 = 17;
const SOCK_RAW: u32 = 3;
const IFNAMSIZ: usize = 16;
const SIOCGIFINDEX: usize = 0x8933;

const sockaddr_ll = extern struct {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [8]u8,
};

const ifreq = extern struct {
    ifr_name: [IFNAMSIZ]u8,
    ifr_ifindex: i32,
    _pad: [20]u8 = [_]u8{0} ** 20,
};

const DiscoveryEvent = struct {
    ipv6_src: [16]u8,
    mesh_src: [16]u8,
    mesh_dst: [16]u8,
    cmd_byte: u8,
    cmd: sip.protocol.Command,
};

fn handleFrame(frame: []const u8) ?DiscoveryEvent {
    if (frame.len < ETH_HLEN) return null;

    const eth_type = (@as(u16, frame[12]) << 8) | frame[13];
    if (eth_type != ETH_P_IPV6) return null;

    const ip = frame[ETH_HLEN..];
    if (ip.len < 40) return null;
    if ((ip[0] >> 4) != 6) return null;
    if (ip[6] != IPPROTO_TCP) return null;

    var ipv6_src: [16]u8 = undefined;
    @memcpy(&ipv6_src, ip[8..24]);

    const tcp = ip[40..];
    if (tcp.len < 20) return null;
    const data_offset = (tcp[12] >> 4) * 4;
    if (data_offset < 20 or tcp.len < data_offset) return null;

    const app = tcp[data_offset..];
    if (app.len < DISCOVERY_HEADER_SIZE) return null;
    if (app[0] != MAGIC) return null;

    const cmd_byte = app[1];
    const cmd = sip.protocol.parseCommand(cmd_byte);

    if (cmd != .discovery) return null;

    var mesh_src: [16]u8 = undefined;
    var mesh_dst: [16]u8 = undefined;
    @memcpy(&mesh_src, app[2..18]);
    @memcpy(&mesh_dst, app[18..34]);

    return DiscoveryEvent{
        .ipv6_src = ipv6_src,
        .mesh_src = mesh_src,
        .mesh_dst = mesh_dst,
        .cmd_byte = cmd_byte,
        .cmd = cmd,
    };
}

fn formatHexAddr(buf: []u8, addr: []const u8) []const u8 {
    var pos: usize = 0;
    for (addr, 0..) |b, j| {
        if (j > 0) {
            buf[pos] = ':';
            pos += 1;
        }
        const s = std.fmt.bufPrint(buf[pos..], "{x:0>2}", .{b}) catch break;
        pos += s.len;
    }
    return buf[0..pos];
}

fn formatIpv6Colon(buf: []u8, addr: [16]u8) []const u8 {
    var pos: usize = 0;
    var i: usize = 0;
    while (i < 16) : (i += 2) {
        if (i > 0) {
            buf[pos] = ':';
            pos += 1;
        }
        const s = std.fmt.bufPrint(buf[pos..], "{x:0>4}", .{(@as(u16, addr[i]) << 8) | addr[i + 1]}) catch break;
        pos += s.len;
    }
    return buf[0..pos];
}

fn logEvent(ev: DiscoveryEvent) void {
    var ip6_buf: [40]u8 = undefined;
    var msrc_buf: [47]u8 = undefined;
    var mdst_buf: [47]u8 = undefined;

    std.debug.print(
        "MESH DISCOVERY magic=0xA9 cmd=0x{x:0>2}({s}) ip6src={s} meshsrc={s} meshdst={s}\n",
        .{
            ev.cmd_byte,
            @tagName(ev.cmd),
            formatIpv6Colon(&ip6_buf, ev.ipv6_src),
            formatHexAddr(&msrc_buf, &ev.mesh_src),
            formatHexAddr(&mdst_buf, &ev.mesh_dst),
        },
    );
}

fn toMeshAddr(mesh16: [16]u8) [registry.MESH_ADDR_SIZE]u8 {
    var out: [registry.MESH_ADDR_SIZE]u8 = [_]u8{0} ** registry.MESH_ADDR_SIZE;
    @memcpy(out[0..16], &mesh16);
    return out;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const iface: []const u8 = if (args.len >= 2) args[1] else "lo";

    std.debug.print("sniffer on {s}, magic=0x{x:0>2}\n", .{ iface, MAGIC });

    const sock_rc = linux.socket(AF_PACKET, SOCK_RAW, std.mem.nativeToBig(u16, ETH_P_ALL));
    const sock_signed: isize = @bitCast(sock_rc);
    if (sock_signed < 0) {
        std.debug.print("socket() failed (errno {}), need root\n", .{-sock_signed});
        return error.SocketFailed;
    }
    const sock: i32 = @intCast(sock_rc);
    defer _ = linux.close(sock);

    var ifr: ifreq = std.mem.zeroes(ifreq);
    const copy_len = @min(iface.len, IFNAMSIZ - 1);
    @memcpy(ifr.ifr_name[0..copy_len], iface[0..copy_len]);

    const ioctl_rc = linux.ioctl(sock, SIOCGIFINDEX, @intFromPtr(&ifr));
    const ioctl_signed: isize = @bitCast(ioctl_rc);
    if (ioctl_signed < 0) {
        std.debug.print("interface '{s}' not found\n", .{iface});
        return error.InterfaceNotFound;
    }

    var sll: sockaddr_ll = std.mem.zeroes(sockaddr_ll);
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = std.mem.nativeToBig(u16, ETH_P_ALL);
    sll.sll_ifindex = ifr.ifr_ifindex;

    const bind_rc = linux.bind(sock, @ptrCast(&sll), @sizeOf(sockaddr_ll));
    const bind_signed: isize = @bitCast(bind_rc);
    if (bind_signed < 0) {
        std.debug.print("bind() failed\n", .{});
        return error.BindFailed;
    }

    var frame_buf: [65536]u8 = undefined;
    while (true) {
        const n_rc = linux.read(sock, &frame_buf, frame_buf.len);
        const n_signed: isize = @bitCast(n_rc);
        if (n_signed <= 0) continue;

        const ev = handleFrame(frame_buf[0..@intCast(n_signed)]) orelse continue;
        logEvent(ev);

        registry.registerDiscovered(io, ev.ipv6_src, toMeshAddr(ev.mesh_src)) catch |err| {
            std.debug.print("registry write failed: {}\n", .{err});
        };
    }
}
