`timescale 1ns / 1ps

module packet_parser_top (
    input  wire        clk,
    input  wire        rst_n,
    
    // AXI-Stream Slave
    input  wire [7:0]  s_axis_tdata,
    input  wire        s_axis_tvalid,
    input  wire        s_axis_tlast,
    
    // Header Outputs
    output reg  [31:0] parsed_src_ip,
    output reg  [31:0] parsed_dst_ip,
    output reg  [15:0] parsed_src_port,
    output reg  [15:0] parsed_dst_port,
    
    // Real-Time Payload Signals
    output reg         payload_valid,
    output reg  [7:0]  payload_data_out,
    output reg         payload_present,
    output reg  [15:0] payload_byte_count,

    // Hardware DPI Engine Outputs
    output wire        dpi_match,
    output wire [7:0]  dpi_rule_id,
    output wire [15:0] dpi_match_offset
);

    reg [15:0] byte_cnt;
    reg [7:0]  ip_protocol;
    reg [5:0]  ip_header_len;
    reg [6:0]  tcp_header_len;
    reg [15:0] payload_start_offset;
    reg        offset_locked;

    // Internal capture RAM for first 64 payload bytes
    reg [7:0] payload_buffer [0:63];
    integer k;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            byte_cnt           <= 16'd0;
            parsed_src_ip      <= 32'd0;
            parsed_dst_ip      <= 32'd0;
            parsed_src_port    <= 16'd0;
            parsed_dst_port    <= 16'd0;
            ip_protocol        <= 8'd0;
            ip_header_len      <= 6'd20;
            tcp_header_len     <= 7'd20;
            payload_start_offset <= 16'hFFFF; // Inactive until computed
            offset_locked      <= 1'b0;
            payload_valid      <= 1'b0;
            payload_data_out   <= 8'd0;
            payload_present    <= 1'b0;
            payload_byte_count <= 16'd0;
            for (k = 0; k < 64; k = k + 1) payload_buffer[k] <= 8'h00;
        end else if (s_axis_tvalid) begin

            // 1. IP Header Fields
            case (byte_cnt)
                16'd14: ip_header_len <= {s_axis_tdata[3:0], 2'b00};
                16'd23: ip_protocol   <= s_axis_tdata;
                16'd26: parsed_src_ip[31:24] <= s_axis_tdata;
                16'd27: parsed_src_ip[23:16] <= s_axis_tdata;
                16'd28: parsed_src_ip[15:8]  <= s_axis_tdata;
                16'd29: parsed_src_ip[7:0]   <= s_axis_tdata;
                16'd30: parsed_dst_ip[31:24] <= s_axis_tdata;
                16'd31: parsed_dst_ip[23:16] <= s_axis_tdata;
                16'd32: parsed_dst_ip[15:8]  <= s_axis_tdata;
                16'd33: parsed_dst_ip[7:0]   <= s_axis_tdata;
            endcase

            // 2. Transport Header Fields (Ports)
            if (byte_cnt == (16'd14 + ip_header_len)) begin
                parsed_src_port[15:8] <= s_axis_tdata;
            end else if (byte_cnt == (16'd14 + ip_header_len + 16'd1)) begin
                parsed_src_port[7:0]  <= s_axis_tdata;
            end else if (byte_cnt == (16'd14 + ip_header_len + 16'd2)) begin
                parsed_dst_port[15:8] <= s_axis_tdata;
            end else if (byte_cnt == (16'd14 + ip_header_len + 16'd3)) begin
                parsed_dst_port[7:0]  <= s_axis_tdata;
            end

            // 3. Dynamic Header Length & Payload Start Locking
            if (ip_protocol == 8'h06 && byte_cnt == (16'd14 + ip_header_len + 16'd12)) begin
                // s_axis_tdata[7:4] is TCP Data Offset (in 32-bit words)
                payload_start_offset <= 16'd14 + ip_header_len + {s_axis_tdata[7:4], 2'b00};
                offset_locked <= 1'b1;
            end else if (ip_protocol == 8'h11 && byte_cnt == (16'd14 + ip_header_len + 16'd7)) begin
                // UDP is always 8 bytes fixed header
                payload_start_offset <= 16'd14 + ip_header_len + 16'd8;
                offset_locked <= 1'b1;
            end

            // 4. Stream and Store Payload
            if (offset_locked && (byte_cnt >= payload_start_offset)) begin
                payload_valid    <= 1'b1;
                payload_data_out <= s_axis_tdata;
                payload_present  <= 1'b1;
                if (payload_byte_count < 16'd64) begin
                    payload_buffer[payload_byte_count[5:0]] <= s_axis_tdata;
                end
                payload_byte_count <= payload_byte_count + 1'b1;
            end else begin
                payload_valid <= 1'b0;
            end

            if (s_axis_tlast) begin
                byte_cnt <= 16'd0;
            end else begin
                byte_cnt <= byte_cnt + 1'b1;
            end
        end else begin
            payload_valid <= 1'b0;
        end
    end

    // -------------------------------------------------------------------------
    // 5. Hardware Deep Packet Inspection (DPI) Core Subsystem Integration
    // Consumes ONLY the extracted payload stream and port metadata from parser.
    // -------------------------------------------------------------------------
    // Compute primary transport port (80 for HTTP, 443 for HTTPS)
    wire [15:0] transport_port = ((parsed_src_port == 16'd80)  || (parsed_dst_port == 16'd80))  ? 16'd80  :
                                 ((parsed_src_port == 16'd443) || (parsed_dst_port == 16'd443)) ? 16'd443 :
                                 (parsed_src_port < parsed_dst_port && parsed_src_port != 16'd0) ? parsed_src_port : parsed_dst_port;

    // Reset DPI state on system reset or at the arrival of byte 0 of a new frame
    wire start_of_frame = s_axis_tvalid && (byte_cnt == 16'd0);
    wire dpi_rst_n      = rst_n && !start_of_frame;

    dpi_engine u_dpi_engine (
        .clk              (clk),
        .rst_n            (dpi_rst_n),
        .payload_valid    (payload_valid),
        .payload_data_in  (payload_data_out),
        .s_axis_tlast     (s_axis_tlast),
        .transport_port   (transport_port),
        .dpi_match        (dpi_match),
        .dpi_rule_id      (dpi_rule_id),
        .dpi_match_offset (dpi_match_offset)
    );

endmodule